#!/usr/bin/env bash
# Set all CPUs to max frequency and governor to performance
# Requires root privileges

set -euo pipefail

# Must run as root
if [[ "$EUID" -ne 0 ]]; then
    echo "Run this script as root (sudo)." >&2
    exit 1
fi

CPU_SYSFS="/sys/devices/system/cpu"

for cpu_path in "$CPU_SYSFS"/cpu[0-9]*; do
    cpufreq_path="$cpu_path/cpufreq"

    # Skip CPUs without cpufreq support
    [[ -d "$cpufreq_path" ]] || continue

    cpu_name="$(basename "$cpu_path")"
    echo "Configuring $cpu_name..."

    # Set governor to performance if supported
    gov_file="$cpufreq_path/scaling_governor"
    avail_gov_file="$cpufreq_path/scaling_available_governors"

    if [[ -f "$gov_file" ]]; then
        if [[ -f "$avail_gov_file" ]] && grep -qw performance "$avail_gov_file"; then
            echo performance > "$gov_file"
            echo "  Governor set to performance"
        else
            echo "  performance governor not available"
        fi
    fi

    # Set current max frequency to hardware max
    max_hw_file="$cpufreq_path/cpuinfo_max_freq"
    max_set_file="$cpufreq_path/scaling_max_freq"
    min_set_file="$cpufreq_path/scaling_min_freq"

    if [[ -f "$max_hw_file" && -f "$max_set_file" ]]; then
        max_freq="$(cat "$max_hw_file")"
        echo "$max_freq" > "$max_set_file"
        echo "  Max frequency set to $max_freq"
    fi

    # Optional: also raise min frequency to max for fixed max clocks
    if [[ -f "$min_set_file" && -f "$max_hw_file" ]]; then
        max_freq="$(cat "$max_hw_file")"
        echo "$max_freq" > "$min_set_file"
        echo "  Min frequency also set to $max_freq"
    fi
done

echo "Done."