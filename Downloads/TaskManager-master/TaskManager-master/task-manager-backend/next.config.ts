import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Add rewrites to proxy API requests during development
  async rewrites() {
    return [
      {
        source: '/api/:path*', // Match all API routes
        destination: 'http://localhost:3000/api/:path*', // Redirect to backend API (change this URL to your backend)
      },
    ];
  },

  // Optional: you can add other configurations as needed
  reactStrictMode: true,
};

export default nextConfig;
