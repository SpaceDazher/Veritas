import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: {
    workerThreads: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
