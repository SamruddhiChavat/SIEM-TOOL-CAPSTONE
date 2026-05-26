# 🚀 Deploying SecureWatch

This is the ultimate deployment guide. SecureWatch relies heavily on an isolated Docker network. 

## Step 1: Initialization
1. Ensure Docker Desktop is running and allocated at least **12GB RAM**.
2. Clone this folder dynamically or move to the generated root.
3. Type:
   ```bash
   ./start.sh
   ```
4. This script triggers the entire topology setup.

## Step 2: Verifying Boot
Wait about 60 seconds, then check the logs.
```bash
docker compose logs -f correlation_engine
```
If you see `[INFO] Successfully loaded 6 rules`, your Brain is online!

## Step 3: View the SOC Dashboard
Navigate to your frontend.
```
http://localhost:3000
```
*(If port 3000 naturally fails on mac localhost due to bind conflicts, just open `docker-compose.yml` and remap `3001:3000`, then `./stop.sh && ./start.sh`).*

## Step 4: Run the Attack Simulator
The SIEM dashboard will naturally be empty because your network hasn't been attacked yet! Let's simulate a massive multi-vector hit.

Open a new terminal tab and run:
```bash
cd attack_simulator/
pip install -r requirements.txt # (if needed)
python3 simulator.py
```

This will blast the containerized `port 5140` logstash udp sniffer with a rapid burst of failed SSH logins simulating an external actor brute forcing.
Wait 33 seconds (the engine polls dynamically every 30s) and watch the UI.

The Critical Counter should light up red. The live feed will trace `SIEM-001: Brute Force Login` attributing the attacker's IP!

## Step 5: Advanced Network Sensors (Real World)
To install sensors on external laptops or servers on your same wifi network:
1. Copy `agent/install_agent.sh` to a linux box or raspberry pi.
2. Change `LOGSTASH_HOST` to the Internal IP of your Mac (e.g. `192.168.0.12`).
3. Run the script! The external machine will instantly start streaming live OS-level activity into the Elasticsearch sink.
