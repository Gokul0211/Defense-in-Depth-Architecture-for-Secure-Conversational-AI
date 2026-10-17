import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  turbopack: {
    rules: {
      "*.{glsl,vert,frag}": { loaders: ["raw-loader"], as: "*.js" },
    },
  },
  webpack(cfg) {
    cfg.module.rules.push({ test: /\.(glsl|vert|frag)$/, type: "asset/source" });
    return cfg;
  },
};

export default config;
