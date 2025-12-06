/*
 * This file is part of cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * CommandBuilder - Safe command line construction utility
 *
 * Provides:
 * - Safe shell command building with proper escaping
 * - Argument validation and sanitization
 * - Support for common command patterns
 * - Prevention of command injection vulnerabilities
 *
 * Usage:
 * {@code
 * String cmd = new CommandBuilder("nmap")
 *     .addFlag("-sS")
 *     .addOption("-p", "80,443")
 *     .addArgument(targetIp)
 *     .build();
 * }
 */
public final class CommandBuilder {

    private static final String TAG = "CommandBuilder";

    // Pattern for safe argument characters
    private static final Pattern SAFE_ARG_PATTERN = Pattern.compile("^[a-zA-Z0-9._/:-]+$");

    // Characters that need escaping in shell
    private static final String SHELL_META_CHARS = "\"'`$\\!&|;()<>{}[]* \t\n\r";

    private final String executable;
    private final List<String> arguments;
    private String workingDirectory;
    private boolean sudoPrefix;
    private int timeout;

    /**
     * Create a new command builder
     *
     * @param executable the executable/command name
     */
    public CommandBuilder(@NonNull String executable) {
        this.executable = validateExecutable(executable);
        this.arguments = new ArrayList<>();
        this.sudoPrefix = false;
        this.timeout = 0;
    }

    /**
     * Add a flag (e.g., -v, --verbose)
     */
    @NonNull
    public CommandBuilder addFlag(@NonNull String flag) {
        if (isValidFlag(flag)) {
            arguments.add(flag);
        }
        return this;
    }

    /**
     * Add multiple flags
     */
    @NonNull
    public CommandBuilder addFlags(@NonNull String... flags) {
        for (String flag : flags) {
            addFlag(flag);
        }
        return this;
    }

    /**
     * Add an option with value (e.g., -p 80 or --port=80)
     */
    @NonNull
    public CommandBuilder addOption(@NonNull String option, @Nullable String value) {
        if (value == null || value.isEmpty()) {
            return this;
        }
        if (isValidFlag(option)) {
            arguments.add(option);
            arguments.add(escapeArgument(value));
        }
        return this;
    }

    /**
     * Add an option with value using equals sign (e.g., --port=80)
     */
    @NonNull
    public CommandBuilder addOptionEquals(@NonNull String option, @Nullable String value) {
        if (value == null || value.isEmpty()) {
            return this;
        }
        if (isValidFlag(option)) {
            arguments.add(option + "=" + escapeArgument(value));
        }
        return this;
    }

    /**
     * Add a positional argument
     */
    @NonNull
    public CommandBuilder addArgument(@Nullable String argument) {
        if (argument != null && !argument.isEmpty()) {
            arguments.add(escapeArgument(argument));
        }
        return this;
    }

    /**
     * Add multiple positional arguments
     */
    @NonNull
    public CommandBuilder addArguments(@NonNull String... args) {
        for (String arg : args) {
            addArgument(arg);
        }
        return this;
    }

    /**
     * Add a list of arguments
     */
    @NonNull
    public CommandBuilder addArguments(@NonNull List<String> args) {
        for (String arg : args) {
            addArgument(arg);
        }
        return this;
    }

    /**
     * Add a raw (unescaped) argument - use with caution
     * Only use for trusted, pre-validated input
     */
    @NonNull
    public CommandBuilder addRaw(@NonNull String raw) {
        arguments.add(raw);
        return this;
    }

    /**
     * Add an IP address argument with validation
     */
    @NonNull
    public CommandBuilder addIpAddress(@Nullable String ip) {
        if (ip != null && NetworkHelper.isValidIP(ip)) {
            arguments.add(ip);
        }
        return this;
    }

    /**
     * Add a port argument with validation
     */
    @NonNull
    public CommandBuilder addPort(int port) {
        if (NetworkHelper.isValidPort(port)) {
            arguments.add(String.valueOf(port));
        }
        return this;
    }

    /**
     * Add a port range (e.g., "80-443")
     */
    @NonNull
    public CommandBuilder addPortRange(int startPort, int endPort) {
        if (NetworkHelper.isValidPort(startPort) && NetworkHelper.isValidPort(endPort)) {
            arguments.add(startPort + "-" + endPort);
        }
        return this;
    }

    /**
     * Add a file path argument with validation
     */
    @NonNull
    public CommandBuilder addFilePath(@Nullable String path) {
        if (path != null && isValidPath(path)) {
            arguments.add(escapeArgument(path));
        }
        return this;
    }

    /**
     * Set working directory for command
     */
    @NonNull
    public CommandBuilder setWorkingDirectory(@Nullable String directory) {
        if (directory != null && isValidPath(directory)) {
            this.workingDirectory = directory;
        }
        return this;
    }

    /**
     * Add sudo prefix
     */
    @NonNull
    public CommandBuilder sudo() {
        this.sudoPrefix = true;
        return this;
    }

    /**
     * Set command timeout in seconds
     */
    @NonNull
    public CommandBuilder timeout(int seconds) {
        this.timeout = seconds;
        return this;
    }

    /**
     * Add conditional flag (only added if condition is true)
     */
    @NonNull
    public CommandBuilder addFlagIf(boolean condition, @NonNull String flag) {
        if (condition) {
            addFlag(flag);
        }
        return this;
    }

    /**
     * Add conditional option
     */
    @NonNull
    public CommandBuilder addOptionIf(boolean condition, @NonNull String option, @Nullable String value) {
        if (condition) {
            addOption(option, value);
        }
        return this;
    }

    /**
     * Build the command as a single string
     */
    @NonNull
    public String build() {
        StringBuilder sb = new StringBuilder();

        // Working directory prefix
        if (workingDirectory != null) {
            sb.append("cd ").append(escapeArgument(workingDirectory)).append(" && ");
        }

        // Timeout prefix
        if (timeout > 0) {
            sb.append("timeout ").append(timeout).append(" ");
        }

        // Sudo prefix
        if (sudoPrefix) {
            sb.append("sudo ");
        }

        // Executable
        sb.append(executable);

        // Arguments
        for (String arg : arguments) {
            sb.append(" ").append(arg);
        }

        return sb.toString();
    }

    /**
     * Build the command as an array (for ProcessBuilder)
     */
    @NonNull
    public String[] buildArray() {
        List<String> cmd = new ArrayList<>();

        if (sudoPrefix) {
            cmd.add("sudo");
        }

        cmd.add(executable);
        cmd.addAll(arguments);

        return cmd.toArray(new String[0]);
    }

    /**
     * Build with shell wrapper
     */
    @NonNull
    public String buildWithShell() {
        return "sh -c " + escapeArgument(build());
    }

    /**
     * Get argument count
     */
    public int getArgumentCount() {
        return arguments.size();
    }

    /**
     * Clear all arguments
     */
    @NonNull
    public CommandBuilder clear() {
        arguments.clear();
        return this;
    }

    @NonNull
    @Override
    public String toString() {
        return build();
    }

    // ==================== Static Utility Methods ====================

    /**
     * Escape a string for safe use in shell commands
     */
    @NonNull
    public static String escapeArgument(@Nullable String arg) {
        if (arg == null || arg.isEmpty()) {
            return "''";
        }

        // If it's already safe, return as-is
        if (SAFE_ARG_PATTERN.matcher(arg).matches()) {
            return arg;
        }

        // Use single quotes for escaping
        // Single quotes in the string need special handling
        StringBuilder sb = new StringBuilder("'");
        for (char c : arg.toCharArray()) {
            if (c == '\'') {
                sb.append("'\\''");
            } else {
                sb.append(c);
            }
        }
        sb.append("'");

        return sb.toString();
    }

    /**
     * Escape for double-quoted context
     */
    @NonNull
    public static String escapeDoubleQuoted(@Nullable String arg) {
        if (arg == null || arg.isEmpty()) {
            return "\"\"";
        }

        StringBuilder sb = new StringBuilder("\"");
        for (char c : arg.toCharArray()) {
            if (c == '"' || c == '\\' || c == '$' || c == '`') {
                sb.append('\\');
            }
            sb.append(c);
        }
        sb.append("\"");

        return sb.toString();
    }

    /**
     * Sanitize a string by removing potentially dangerous characters
     */
    @NonNull
    public static String sanitize(@Nullable String input) {
        if (input == null) {
            return "";
        }
        return input.replaceAll("[^a-zA-Z0-9._/:-]", "");
    }

    /**
     * Check if a string contains shell metacharacters
     */
    public static boolean containsMetaCharacters(@Nullable String input) {
        if (input == null) {
            return false;
        }
        for (char c : SHELL_META_CHARS.toCharArray()) {
            if (input.indexOf(c) >= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validate an executable name
     */
    @NonNull
    private static String validateExecutable(@NonNull String executable) {
        if (executable.isEmpty()) {
            throw new IllegalArgumentException("Executable cannot be empty");
        }
        // Only allow alphanumeric, underscore, hyphen, slash, and dot
        if (!executable.matches("^[a-zA-Z0-9_./-]+$")) {
            throw new IllegalArgumentException("Invalid executable name: " + executable);
        }
        return executable;
    }

    /**
     * Validate a flag format
     */
    private static boolean isValidFlag(@NonNull String flag) {
        // Must start with - and contain only allowed characters
        return flag.matches("^--?[a-zA-Z0-9][-a-zA-Z0-9]*$");
    }

    /**
     * Validate a file path
     */
    private static boolean isValidPath(@NonNull String path) {
        // Disallow path traversal and null bytes
        if (path.contains("\0") || path.contains("..")) {
            return false;
        }
        return path.matches("^[a-zA-Z0-9_./-]+$");
    }

    // ==================== Common Command Builders ====================

    /**
     * Create an nmap command builder
     */
    @NonNull
    public static CommandBuilder nmap() {
        return new CommandBuilder("nmap");
    }

    /**
     * Create an arp command builder
     */
    @NonNull
    public static CommandBuilder arp() {
        return new CommandBuilder("arp");
    }

    /**
     * Create a ping command builder
     */
    @NonNull
    public static CommandBuilder ping() {
        return new CommandBuilder("ping");
    }

    /**
     * Create a traceroute command builder
     */
    @NonNull
    public static CommandBuilder traceroute() {
        return new CommandBuilder("traceroute");
    }

    /**
     * Create a netstat command builder
     */
    @NonNull
    public static CommandBuilder netstat() {
        return new CommandBuilder("netstat");
    }

    /**
     * Create an iptables command builder
     */
    @NonNull
    public static CommandBuilder iptables() {
        return new CommandBuilder("iptables").sudo();
    }

    /**
     * Create a hydra command builder
     */
    @NonNull
    public static CommandBuilder hydra() {
        return new CommandBuilder("hydra");
    }
}
