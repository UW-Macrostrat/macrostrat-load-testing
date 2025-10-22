### Usage

- `uv sync`
- Download log file, e.g. last2days.log
- `uv run cli.py simulate last2days.log` will simulate the API requests in the last2days.log
- `uv run cli.py simulate last2days.log -d 10` will cap at ~10 seconds 
- `uv run cli.py simulate last2days.log -m verbose` verbose will print complete logs (instead of summary and failed, which is default)
- `uv run cli.py simulate last2days.log -l 10` will simulate on the first 10 lines of the log file.
- `uv run cli.py simulate last2days.log -t 0.5` will simulate at 0.5x time compression
- `uv run cli.py simulate last2days.log -w 20` will simulate with 20 workers.
- 