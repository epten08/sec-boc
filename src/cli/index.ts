#!/usr/bin/env node

import { config } from "dotenv";
import { Command } from "commander";
import { createRunCommand } from "./commands/run";
import { logger } from "../core/logger";

// Load environment variables from .env file
config();

const VERSION = "1.0.0";

async function main(): Promise<void> {
  const program = new Command();

  program
    .name("sec-bot")
    .description("CLI-based automated security analysis tool")
    .version(VERSION)
    .option("--no-color", "Disable colored output")
    .hook("preAction", (thisCommand) => {
      const opts = thisCommand.opts();
      if (opts.color === false) {
        // Chalk respects NO_COLOR env var
        process.env.NO_COLOR = "1";
      }
    });

  // Add commands
  program.addCommand(createRunCommand());

  // Default action (no command specified)
  program.action(() => {
    program.help();
  });

  // Error handling
  program.exitOverride((err) => {
    if (err.code === "commander.help" || err.code === "commander.version") {
      process.exit(0);
    }
    process.exit(1);
  });

  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    logger.error(`Fatal error: ${(err as Error).message}`);
    process.exit(1);
  }
}

main();
