import re
import time
import requests
import click
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

log_pattern = re.compile(
    r'(?P<ip>\S+) (?:\S+ ){2}\[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referrer>.*?)" "(?P<user_agent>.*?)" "-"'
)

def parse_log_line(line):
    match = log_pattern.match(line)
    if not match:
        return None
    timestamp = datetime.strptime(match['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
    return {
        'ip': match['ip'],
        'timestamp': timestamp,
        'method': match['method'],
        'path': match['path'],
        'status': int(match['status']),
        'size': int(match['size']),
        'referrer': match['referrer'],
        'user_agent': match['user_agent'],
    }

def run_user_session(user_reqs, base_url='https://dev.macrostrat.org',
                     time_compression_factor=1.0,
                     start_time=None, max_duration_seconds=None,
                     mode="verbose"):
    stats = {
        'total': 0,
        'success': 0,
        'fail': 0,
        'response_times': [],
        'errors': []
    }

    user_reqs.sort(key=lambda x: x['timestamp'])

    for i, req in enumerate(user_reqs):
        if start_time and max_duration_seconds:
            if time.time() - start_time > max_duration_seconds:
                if mode == "verbose":
                    click.echo(f"⏱️ Duration limit reached for user session {req['ip']}")
                break

        if i > 0:
            delay = (req['timestamp'] - user_reqs[i - 1]['timestamp']).total_seconds()
            delay *= time_compression_factor
            time.sleep(min(delay, 5))

        url = base_url + req['path']
        headers = {'User-Agent': req['user_agent']}
        stats['total'] += 1

        try:
            req_start = time.time()
            response = requests.request(req['method'], url, headers=headers, timeout=5)
            elapsed = time.time() - req_start
            stats['response_times'].append(elapsed)

            if response.status_code < 400:
                stats['success'] += 1
                if mode == "verbose":
                    click.echo(f"{req['method']} {url} -> {response.status_code} ({elapsed:.2f}s)")
            else:
                stats['fail'] += 1
                stats['errors'].append((url, response.status_code))
                if mode == "verbose":
                    click.echo(f"{req['method']} {url} -> ERROR {response.status_code} ({elapsed:.2f}s)")
        except Exception as e:
            stats['fail'] += 1
            stats['errors'].append((url, str(e)))
            if mode == "verbose":
                click.echo(f"{req['method']} {url} -> EXCEPTION: {e}")

    return stats

def simulate_concurrent_users(log_lines, base_url='https://dev.macrostrat.org',
                              max_workers=5,
                              time_compression_factor=1.0,
                              max_duration_seconds=None,
                              mode="verbose"):
    parsed = [parse_log_line(line) for line in log_lines]
    parsed = [p for p in parsed if p is not None]

    sessions = defaultdict(list)
    for req in parsed:
        sessions[req['ip']].append(req)

    if mode == "verbose":
        click.echo(f"Simulating {len(sessions)} users with up to {max_workers} concurrent sessions...")
        click.echo(f"Time compression factor: {time_compression_factor}")
        if max_duration_seconds:
            click.echo(f"Max test duration: {max_duration_seconds} seconds\n")

    start_time = time.time()

    all_stats = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(run_user_session, reqs, base_url,
                            time_compression_factor,
                            start_time, max_duration_seconds,
                            mode)
            for reqs in sessions.values()
        ]
        for future in futures:
            all_stats.append(future.result())

    # Aggregate results
    final = {'total': 0, 'success': 0, 'fail': 0, 'response_times': [], 'errors': []}
    for stats in all_stats:
        final['total'] += stats['total']
        final['success'] += stats['success']
        final['fail'] += stats['fail']
        final['response_times'].extend(stats['response_times'])
        final['errors'].extend(stats['errors'])

    click.echo("\n--- Simulation Summary ---")
    click.echo(f"Total requests:   {final['total']}")
    click.echo(f"Successful:       {final['success']}")
    click.echo(f"Failed:           {final['fail']}")
    if final['response_times']:
        avg = sum(final['response_times']) / len(final['response_times'])
        click.echo(f"Average response: {avg:.2f} s")
        click.echo(f"Max response:     {max(final['response_times']):.2f} s")
        click.echo(f"Min response:     {min(final['response_times']):.2f} s")
    if final['errors']:
        click.echo("Some errors encountered:")
        for url, err in final['errors'][:100]:
            click.echo(f"  - {url}: {err}")
        if len(final['errors']) > 100:
            click.echo(f"  ... and {len(final['errors']) - 100} more")


# -------------------------
# CLI
# -------------------------
@click.group()
@click.version_option()
def cli():
    """Use this CLI tool to turn API logs into load tests."""


@cli.command("simulate")
@click.argument("logfile", type=click.Path(exists=True), metavar="LOGFILE")
@click.option("--base-url", "-u", default="https://dev.macrostrat.org",
              show_default=True,
              help="Base URL to replay requests against (e.g. https://example.com).")
@click.option("--max-workers", "-w", default=10, show_default=True,
              help="Maximum number of concurrent simulated users (parallel sessions).")
@click.option("--time-compression-factor", "-t", default=1.0, show_default=True,
              help="Speed multiplier for replay timing. "
                   "1.0 = real-time, 0.5 = 2x faster, 0.25 = 4x faster, etc.")
@click.option("--max-duration-seconds", "-d", default=None, type=int,
              help="Optional cap on test duration in seconds. Example: -d 300 stops after 5 minutes.")
@click.option("--mode", "-m", type=click.Choice(["summary","verbose"]),
              default="summary", show_default=True,
              help="Output mode. 'verbose' prints every request; 'summary' only prints summary and failed requests.")
@click.option("--lines", "-l", default=None, type=int,
              help="Optional limit on number of log lines to process (for testing).")

def simulate_command(logfile, base_url, max_workers, time_compression_factor, max_duration_seconds, mode, lines):
    """Simulate concurrent users from an API access log file."""
    with open(logfile) as f:
        if lines:
            log_lines = [f.readline() for _ in range(lines)]
        else:
            log_lines = f.readlines()
        simulate_concurrent_users(
            log_lines,
            base_url=base_url,
            max_workers=max_workers,
            time_compression_factor=time_compression_factor,
            max_duration_seconds=max_duration_seconds,
            mode=mode,
        )


if __name__ == "__main__":
    cli()
