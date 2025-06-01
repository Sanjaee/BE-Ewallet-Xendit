require("dotenv").config();
const express = require("express");
const {
  initializeConnections,
  setupGracefulShutdown,
} = require("./config/server");
const app = require("./config/app");

const PORT = process.env.PORT || 3000;

// Initialize connections and start server
const startServer = async () => {
  try {
    // Test all connections
    await initializeConnections();

    // Start server
    const server = app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });

    // Setup graceful shutdown
    setupGracefulShutdown(server);
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

startServer();
