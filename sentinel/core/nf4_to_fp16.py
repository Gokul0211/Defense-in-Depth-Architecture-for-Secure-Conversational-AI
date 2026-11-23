"""
Convert the pre-quantized nf4 copy of the local 4B (bitsandbytes 4-bit, double-quantized, as saved by transformers) into a
plain fp16 checkpoint, with PyTorch only -- no bitsandbytes, no CUDA (2026-11-23).

WHY. The local model runs on an NVIDIA GPU through bitsandbytes' 4-bit kernels. A machine without CUDA (an Apple-silicon
Mac running PyTorch's MPS backend) can run the SAME effective weights in fp16: an nf4 kernel dequantizes each weight to
fp16 before it multiplies, so the fp16 tensors written here are exactly the values the 4-bit model computes with. The
conversion is checked tensor by tensor against bitsandbytes' own dequantize_4bit (scratch/rca/l3/_nf4_check.py: equal).

FORMAT (one quantized weight W, out x in, blocksize 64, nested blocksize 256):
  W                          uint8 (n/2, 1)   two 4-bit codes per byte, the FIRST element in the HIGH nibble
  W.quant_map                fp32 (16)        the NF4 code book
  W.absmax                   uint8 (n/64)     8-bit codes of the per-block absmax
  W.nested_quant_map         fp32 (256)       the 8-bit dynamic code book of the absmax
  W.nested_absmax            fp32 (n/64/256)  per-256-block scale of the absmax
  W.quant_state.bitsandbytes__nf4  uint8      JSON: shape, dtype, blocksize, nested_blocksize, nested_offset, ...
  absmax[b] = nested_quant_map[absmax_code[b]] * nested_absmax[b // 256] + nested_offset           (fp32)
  W[i]      = fp16( quant_map[code[i]] * absmax[i // 64] )                                          (fp32 product)
Without double quantization (no nested_* tensors) W.absmax is the fp32 absmax itself.
bitsandbytes' dequantize_4bit returns W in the weight's ORIGINAL dtype (quant_state "dtype"; bf16 for a model loaded
in bf16) and the 4-bit matmul then casts it to the compute dtype (the input's, fp16 here). The written weight is
therefore compute_dtype( state_dtype( fp32 product ) ) -- exactly the tensor the 4-bit model multiplies with.
Every other tensor (embeddings, norms, lm_head) is copied unchanged. DST/nf4_converted.json lists the converted
(quantized) weights and the compute dtype; load_model() rebuilds the 4-bit model's arithmetic from it: the quantized
linears multiply in the compute dtype (input cast in, output cast back, as bitsandbytes' Linear4bit), everything else
runs in the dtype the measured code loaded the model in (`rest_dtype`).

Run: python -m sentinel.core.nf4_to_fp16 SRC_DIR DST_DIR     (the Mac runner calls convert() once per model)
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

SUFFIXES = (".absmax", ".quant_map", ".nested_absmax", ".nested_quant_map", ".quant_state.bitsandbytes__nf4")


def _state(raw) -> dict:
    import torch
    return json.loads(bytes(raw.to(torch.uint8).flatten().tolist()).decode("utf-8"))


_DT = {"float16": "float16", "torch.float16": "float16", "bfloat16": "bfloat16", "torch.bfloat16": "bfloat16",
       "float32": "float32", "torch.float32": "float32"}


def _dtype(name):
    import torch
    return getattr(torch, _DT[str(name)])


def dequantize(packed, absmax_codes, nested_absmax, nested_quant_map, quant_map, state):
    """The weight from the stored nf4 components, in the weight's original dtype (state "dtype"; see the module
    docstring). nested_absmax / nested_quant_map are None when the checkpoint has no double quantization."""
    import torch
    bs, nbs = int(state["blocksize"]), int(state.get("nested_blocksize", 256))
    if nested_absmax is None:
        absmax = absmax_codes.float().flatten()
    else:
        offset = float(state.get("nested_offset", 0.0))
        a = absmax_codes.to(torch.long).flatten()
        nb = torch.arange(a.numel()) // nbs
        absmax = nested_quant_map.float()[a] * nested_absmax.float()[nb] + offset
    p = packed.to(torch.uint8).flatten()
    codes = torch.stack([(p >> 4) & 0x0F, p & 0x0F], dim=1).flatten().to(torch.long)
    shape = [int(x) for x in state["shape"]]
    n = 1
    for s in shape:
        n *= s
    codes = codes[:n]
    blk = torch.arange(n) // bs
    w = quant_map.float()[codes] * absmax[blk]
    return w.to(_dtype(state.get("dtype", "float16"))).reshape(shape)


def iter_converted(src: Path, compute_dtype: str = "float16"):
    """Yield (name, tensor, quantized?) for every weight of the checkpoint; the nf4 ones dequantized and cast to the
    compute dtype."""
    from safetensors import safe_open
    cd = _dtype(compute_dtype)
    for f in sorted(src.glob("*.safetensors")):
        with safe_open(str(f), "pt") as h:
            keys = list(h.keys())
            quantized = {k for k in keys if f"{k}.quant_state.bitsandbytes__nf4" in keys}
            for k in keys:
                if k.endswith(SUFFIXES):
                    continue
                if k in quantized:
                    st = _state(h.get_tensor(f"{k}.quant_state.bitsandbytes__nf4"))
                    nested = f"{k}.nested_absmax" in keys
                    w = dequantize(h.get_tensor(k), h.get_tensor(f"{k}.absmax"),
                                   h.get_tensor(f"{k}.nested_absmax") if nested else None,
                                   h.get_tensor(f"{k}.nested_quant_map") if nested else None,
                                   h.get_tensor(f"{k}.quant_map"), st)
                    yield k, w.to(cd), True
                else:
                    yield k, h.get_tensor(k), False


SHARD_BYTES = 1 << 30                  # ~1 GB shards: the conversion never holds more than one shard in memory


def convert(src, dst) -> dict:
    """Write DST: the converted checkpoint in ~1 GB safetensors shards (+ index), config.json without
    quantization_config, the tokenizer / chat template / generation config, and nf4_converted.json."""
    import torch
    from safetensors.torch import save_file
    src, dst = Path(src), Path(dst)
    cfg = json.loads((src / "config.json").read_text(encoding="utf-8"))
    qc = cfg.pop("quantization_config", None) or {}
    compute = str(qc.get("bnb_4bit_compute_dtype", "float16")).replace("torch.", "")
    tmp = dst.with_name(dst.name + ".partial")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    shards, wmap = [], {}
    state = {"cur": {}, "size": 0}
    quantized, rest = [], {}

    def flush():
        if state["cur"]:
            name = f"part-{len(shards) + 1:05d}.safetensors"
            save_file(state["cur"], str(tmp / name), metadata={"format": "pt"})
            shards.append(name)
            for k in state["cur"]:
                wmap[k] = name
        state["cur"], state["size"] = {}, 0

    for k, t, q in iter_converted(src, compute):
        t = t.contiguous()
        if q:
            quantized.append(k)
        elif t.is_floating_point():
            dn = str(t.dtype).replace("torch.", "")
            rest[dn] = rest.get(dn, 0) + 1
        state["cur"][k] = t
        state["size"] += t.numel() * t.element_size()
        if state["size"] >= SHARD_BYTES:
            flush()
    flush()
    final = {}
    for i, name in enumerate(shards):                 # model-0000i-of-0000n names, as transformers writes them
        new = f"model-{i + 1:05d}-of-{len(shards):05d}.safetensors"
        (tmp / name).rename(tmp / new)
        final[name] = new
    total = sum((tmp / n).stat().st_size for n in final.values())
    (tmp / "model.safetensors.index.json").write_text(json.dumps(
        {"metadata": {"total_size": total}, "weight_map": {k: final[v] for k, v in wmap.items()}}, indent=1),
        encoding="utf-8")
    cfg["dtype"] = compute
    (tmp / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    for name in ("tokenizer.json", "tokenizer_config.json", "chat_template.jinja", "generation_config.json",
                 "special_tokens_map.json", "vocab.json", "merges.txt", "added_tokens.json", "judge_dtypes.json"):
        if (src / name).exists():
            shutil.copy2(src / name, tmp / name)
    man = {"source": src.name, "compute_dtype": compute, "quantized": quantized, "unquantized_float_dtypes": rest,
           "shards": len(shards), "bytes": total, "torch": torch.__version__}
    (tmp / "nf4_converted.json").write_text(json.dumps(man, indent=1), encoding="utf-8")
    if dst.exists():
        shutil.rmtree(dst)
    tmp.rename(dst)
    return {"tensors": len(wmap), "quantized": len(quantized), "compute_dtype": compute, "rest": rest,
            "shards": len(shards), "dst": str(dst)}


def _half_forward(self, x):
    """bitsandbytes Linear4bit.forward with the weight already dequantized: the input cast to the compute dtype, the
    product in it, the output cast back to the input's dtype."""
    import torch.nn.functional as F
    b = None if self.bias is None else self.bias.to(self.weight.dtype)
    return F.linear(x.to(self.weight.dtype), self.weight, b).to(x.dtype)


def load_model(path, device: str, rest_dtype):
    """The converted model on `device`, computing as the 4-bit model did: every converted linear multiplies in the
    compute dtype; everything else is in `rest_dtype` -- the dtype the measured code loaded the model in (the local 4B:
    fp16, given explicitly; Granite: transformers' "auto", i.e. its bf16 checkpoint dtype)."""
    import types
    import torch
    from safetensors import safe_open
    from transformers import AutoModelForCausalLM
    path = Path(path)
    man = json.loads((path / "nf4_converted.json").read_text(encoding="utf-8"))
    cd = _dtype(man["compute_dtype"])
    rd = _dtype(str(rest_dtype).replace("torch.", ""))
    model = AutoModelForCausalLM.from_pretrained(str(path), dtype=rd, device_map={"": device}).eval()
    if rd == cd:
        return model                                  # one dtype throughout: the plain load is the 4-bit arithmetic
    idx = json.loads((path / "model.safetensors.index.json").read_text(encoding="utf-8"))["weight_map"]
    by_file = {}
    for k in man["quantized"]:
        by_file.setdefault(idx[k], []).append(k)
    with torch.no_grad():
        for fname, keys in by_file.items():
            with safe_open(str(path / fname), "pt") as h:
                for k in keys:
                    mod = model.get_submodule(k.rsplit(".", 1)[0])
                    mod.weight = torch.nn.Parameter(h.get_tensor(k).to(device), requires_grad=False)
                    mod.forward = types.MethodType(_half_forward, mod)
    return model


if __name__ == "__main__":
    print(convert(sys.argv[1], sys.argv[2]))
