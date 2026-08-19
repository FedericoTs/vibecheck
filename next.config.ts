import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Pin the workspace root to this project so Next ignores unrelated lockfiles
  // higher up the filesystem (avoids the "inferred workspace root" warning).
  turbopack: {
    root: import.meta.dirname,
  },
};

export default nextConfig;
