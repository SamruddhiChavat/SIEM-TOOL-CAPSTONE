# SOC Dashboard - Deployment & Setup Guide

## ✅ Implementation Checklist

### Backend (FastAPI)
- [x] Enhanced `/api/v1/dashboard/summary` endpoint
- [x] Security Posture Score calculation
- [x] Alert Velocity Detection (spike/quiet)
- [x] MTTD calculation with raw event correlation
- [x] MTTR calculation for closed alerts
- [x] MITRE coverage analysis by tactic
- [x] Alert noise ratio (false positive tracking)
- [x] Threat ranking by urgency score
- [x] Error handling and timeout protection

### Frontend (React/TypeScript)
- [x] Hero Security Posture Score card with gauge visualization
- [x] Alert Velocity warning banner
- [x] Key metrics cards (MTTD, MTTR, Noise, Alerts)
- [x] MITRE ATT&CK 11-tactic heatmap with blind spot detection
- [x] Event volume timeline chart
- [x] Top threats table ranked by urgency
- [x] Responsive grid layout
- [x] Auto-refresh every 60 seconds
- [x] Last updated timestamp

### Data Requirements
- [x] Elasticsearch indices: `siem-logs-*`, `siem-alerts-*`
- [x] Alert fields: timestamp, severity, status, rule_id, mitre_tactic, raw_event_ids
- [x] Asset fields: entity_id, risk_score
- [x] Rules data: YAML rules with MITRE mapping

---

## 🚀 Quick Start

### 1. Backend Setup

The backend automatically handles all calculations in the `/api/v1/dashboard/summary` endpoint.

**Verify Environment Variables:**
```bash
export ELASTICSEARCH_HOSTS=http://elasticsearch:9200
export LOG_LEVEL=INFO
```

**Start Backend (if not already running):**
```bash
cd /Users/jesalshah/Documents/Secure\ watch/realsiem/backend
pip install -r requirements.txt
python main.py
```

Backend should be available at: `http://localhost:8000`

### 2. Frontend Setup

No special setup needed - the Dashboard component uses the standard API endpoint.

**Start Frontend (if not already running):**
```bash
cd /Users/jesalshah/Documents/Secure\ watch/sentinel-watch
npm install
npm run dev
```

Frontend should be available at: `http://localhost:5173`

### 3. Access Dashboard

Navigate to: `http://localhost:5173/dashboard`

---

## 📊 Expected Data Flow

```
┌──────────────────────┐
│  Elasticsearch       │
│  - siem-alerts-*    │◄─── Alert documents with metadata
│  - siem-logs-*      │◄─── Raw event logs with @timestamp
└──────────┬───────────┘
           │
           │ HTTP/REST
           ▼
┌──────────────────────────────────────┐
│  FastAPI Backend                      │
│  /api/v1/dashboard/summary           │
│  ├─ Query alerts (24h, 7d)          │
│  ├─ Calculate posture score          │
│  ├─ Analyze velocity patterns        │
│  ├─ Correlate with raw events (MTTD) │
│  ├─ Aggregate metrics                │
│  └─ Return JSON payload              │
└──────────┬───────────────────────────┘
           │
           │ JSON
           ▼
┌──────────────────────────────────────┐
│  React Frontend                       │
│  Dashboard Component                 │
│  ├─ Display posture gauge            │
│  ├─ Show velocity banner             │
│  ├─ Render MITRE heatmap             │
│  ├─ Plot event timeline              │
│  ├─ List ranked threats              │
│  └─ Auto-refresh (60s)               │
└──────────────────────────────────────┘
```

---

## 🔧 Configuration

### Backend Tuning (dashboard.py)

Edit these constants in the backend router if needed:

```python
# For alert velocity thresholds
SPIKE_THRESHOLD = 2.0           # Alerts > 2x average = spike
QUIET_THRESHOLD = 0.1           # Alerts < 0.1x average = quiet
QUIET_MIN_BASELINE = 5          # Only flag quiet if avg > 5

# For scoring
SECURITY_POSTURE_WEIGHTS = {
    "critical_alert": -8,
    "high_alert": -4,
    "asset_over_80": -3,
    "dead_rule": -1
}

# MITRE coverage thresholds
COVERAGE_BLIND_SPOT = 0         # 0 rules = blind spot
COVERAGE_LOW = 1                # 1 rule = low
COVERAGE_MEDIUM = 3             # 2-3 rules = medium
COVERAGE_GOOD = 4               # 4+ rules = good

# Time windows
MTTD_WINDOW_HOURS = 24
MTTR_WINDOW_DAYS = 7
COVERAGE_WINDOW_DAYS = 7
NOISE_WINDOW_DAYS = 7
```

### Frontend Customization (Dashboard.tsx)

Edit color schemes and thresholds:

```typescript
// Severity colors (update color scheme if needed)
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  // ...
};

// Auto-refresh interval (in milliseconds)
const REFRESH_INTERVAL = 60000;  // 60 seconds

// WebSocket connection
const WS_URL = "ws://localhost:8000/api/alerts/ws";
```

---

## 🧪 Testing

### Test with Sample Data

To verify the dashboard works without live data:

**1. Populate test alerts in Elasticsearch:**

```bash
curl -X POST "http://localhost:9200/siem-alerts-test/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-10-15T14:00:00Z",
    "severity": "critical",
    "status": "open",
    "rule_id": "SIEM-001",
    "rule_name": "Test Critical Alert",
    "mitre_tactic": "Execution",
    "source_ip": "192.168.1.100",
    "asset_risk_score": 85
  }'
```

**2. Check dashboard endpoint:**

```bash
curl http://localhost:8000/api/v1/dashboard/summary | jq
```

**3. Verify response contains all fields:**
- `security_posture` with score
- `alert_velocity` with status
- `mttd` with metrics
- `mttr` with metrics
- `mitre_coverage` with all 11 tactics
- `alert_noise_ratio` with FP data
- `top_threats` array

### Manual Testing Checklist

- [ ] Dashboard loads without errors
- [ ] Security Posture score displays (0-100)
- [ ] Alert Velocity banner appears when spike detected
- [ ] MTTD shows time in minutes
- [ ] MTTR shows time in hours
- [ ] MITRE heatmap shows all 11 tactics
- [ ] Top Threats are sorted by urgency
- [ ] Click "Investigate" navigates to incident
- [ ] Auto-refresh updates timestamp every 60s
- [ ] Responsive on mobile (if applicable)

---

## 🔍 Troubleshooting

### Dashboard Shows "Error Connecting to Backend"

**Cause:** Backend API not responding

**Fix:**
```bash
# Check backend is running
curl http://localhost:8000/health

# Check Elasticsearch is accessible
curl http://localhost:9200/_cluster/health
```

### MTTD Always Shows 0

**Cause:** Raw event correlation not finding matching logs

**Why:** Need `raw_event_ids` field in alerts

**Fix:**
- Ensure correlation engine populates `raw_event_ids` when creating alerts
- Fallback: Backend assumes ~15 second detection latency

### MTTR Shows 0 Hours

**Cause:** No closed alerts in last 7 days

**Fix:**
- Close some test alerts manually
- Or use older data window if testing with historical data

### MITRE Coverage All "0"

**Cause:** Alerts don't have `mitre_tactic` field

**Fix:**
- Check rule-loader adds MITRE mapping
- Verify correlation engine enriches with MITRE data

### Noise Ratio Not Calculating

**Cause:** Resolution notes not containing FP keywords

**Cause:**
- Manually close test alerts with note: "False Positive - benign"
- Or update noise calculation to look for custom status values

---

## 📈 Performance Tuning

### Optimize Backend Queries

If dashboard is slow:

```python
# Add caching for MITRE coverage (expensive aggregation)
from functools import lru_cache

@lru_cache(maxsize=1)
async def get_mitre_coverage_cached():
    # Cache for 5 minutes
    # ...

# Use smaller time windows for faster results
MTTD_WINDOW_HOURS = 12  # Instead of 24
COVERAGE_WINDOW_DAYS = 3  # Instead of 7
```

### Elasticsearch Index Optimization

```bash
# Create alias for faster queries
curl -X POST "http://localhost:9200/_aliases" \
  -H "Content-Type: application/json" \
  -d '{
    "actions": [{
      "add": {
        "index": "siem-alerts-*",
        "alias": "dashboard-alerts"
      }
    }]
  }'
```

### Frontend Performance

- Dashboard uses React.memo for components (already optimized)
- Chart rendering is efficient with Recharts
- No unnecessary re-renders with proper useCallback

---

## 🔐 Security Notes

### Data Access

- Backend queries Elasticsearch directly (assumes internal network)
- WebSocket requires authentication in production
- Add API key validation:

```python
from fastapi import Depends, HTTPException

async def verify_api_key(api_key: str = Header(...)):
    if api_key != os.getenv("DASHBOARD_API_KEY"):
        raise HTTPException(status_code=403, detail="Invalid API key")
```

### Rate Limiting

Add rate limit to prevent dashboard from overwhelming backend:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
router.get("/summary")
@limiter.limit("10/minute")  # Max 10 requests/minute
async def get_dashboard_summary():
    # ...
```

---

## 📚 Additional Resources

- MITRE ATT&CK: https://attack.mitre.org
- Elasticsearch docs: https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html
- FastAPI: https://fastapi.tiangolo.com
- React Recharts: https://recharts.org

---

## 🎯 Next Steps for Enhancement

1. **Add historical trending**
   - Compare current metrics to same day last week
   - Show trend arrows and % change

2. **Implement drill-down**
   - Click on MITRE tactic → see associated rules
   - Click on alert → full incident details

3. **Add alerting**
   - Notify analysts when posture score drops
   - Alert when spike is detected

4. **Multi-tenancy**
   - Support multiple organizations/teams
   - Filter by team in dashboard

5. **Customizable widgets**
   - Let analysts select which metrics to display
   - Save dashboard preferences

6. **Export/Reporting**
   - Export dashboard as PDF report
   - Schedule daily email summaries

---

## ✅ Verification Checklist - Final

- [x] Backend code has valid Python syntax
- [x] Frontend code has valid TypeScript (ignoring library warnings)
- [x] All API endpoints defined
- [x] All UI components implemented
- [x] Auto-refresh implemented
- [x] Error handling in place
- [x] Responsive design applied
- [x] Documentation complete

**Status:** ✅ COMPLETE AND READY FOR TESTING
