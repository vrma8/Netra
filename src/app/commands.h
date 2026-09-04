// SPDX-License-Identifier: MIT
// app/commands.h : internal declarations of the sub-command entry points.
#pragma once

#include <string>
#include <vector>

#include "netra/app/cli.h"

namespace netra::app {

int cmdInterfaces(const std::vector<std::string>& args, CommandContext& context);
int cmdRoutes(const std::vector<std::string>& args, CommandContext& context);
int cmdArp(const std::vector<std::string>& args, CommandContext& context);
int cmdHosts(const std::vector<std::string>& args, CommandContext& context);
int cmdScan(const std::vector<std::string>& args, CommandContext& context);
int cmdCapture(const std::vector<std::string>& args, CommandContext& context);
int cmdAnalyze(const std::vector<std::string>& args, CommandContext& context);
int cmdFlows(const std::vector<std::string>& args, CommandContext& context);
int cmdStats(const std::vector<std::string>& args, CommandContext& context);
int cmdFilters(const std::vector<std::string>& args, CommandContext& context);
int cmdDashboard(const std::vector<std::string>& args, CommandContext& context);
int cmdStore(const std::vector<std::string>& args, CommandContext& context);
int cmdSelftest(const std::vector<std::string>& args, CommandContext& context);
int cmdVersion(const std::vector<std::string>& args, CommandContext& context);
int cmdDemo(const std::vector<std::string>& args, CommandContext& context);

}  // namespace netra::app
