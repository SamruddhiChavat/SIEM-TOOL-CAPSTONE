# SOC Dashboard - Complete Feature Guide

## 🎯 Real-Time Security Operations Center Dashboard

This dashboard provides enterprise-grade SIEM analytics similar to Splunk ES Security Posture and Wazuh Overview, featuring advanced threat detection and security metrics.

### **1. SECURITY POSTURE SCORE (0-100)**

**Display:** Large hero card with color-coded gauge
**Calculation Formula:**
- Start: 100 points
- Each CRITICAL alert: -8 points
- Each HIGH alert: -4 points  
- Each asset with risk_score > 80: -3 points
- Each dead rule (0 alerts in 7 days): -1 point
- Final: Clamped to 0-100 range

**Color Coding:**
- 🟢 80-100: HEALTHY (Green)
- 🟡 60-79: FAIR (Yellow)
- 🟠 40-59: DEGRADED (Orange)
- 🔴 0-39: CRITICAL (Red)

**Insights Provided:**
- Breakout of contributing factors
- Trend vs. previous day
- Quick drill-down to specific issues

---

### **2. ALERT VELOCITY DETECTION**

**Display:** Dynamic warning banner when anomalies detected
**Metric:** Real-time alerts/hour compared to 7-day average for same hour

**Detection Modes:**

#### 🔴 SPIKE DETECTED
- When: Current rate > 2× average
- Severity: CRITICAL
- Message: Shows ratio, current rate, and baseline
- Action: Suggests immediate investigation

#### 🟡 UNUSUALLY QUIET
- When: Current rate < 0.1× average AND historical average > 5 alerts/hr
- Severity: WARNING
- Message: Indicates possible sensor failure or detection gap
- Action: Check agent connectivity and rule health

#### 🟢 NORMAL
- No banner displayed
- Status icon shows normal operations

**Technical Details:**
- Aggregates alerts by hour for last 7 days
- Compares current partial hour to historical median
- Excludes incomplete hour from baseline

---

### **3. MEAN TIME TO DETECT (MTTD)**

**Display:** Metric card with status indicator
**Metric:** Time from first raw log event to alert generation (in minutes)

**Calculation:**
```
MTTD = alert.timestamp - raw_event.@timestamp
Average across all alerts in last 24h
```

**Status Thresholds:**
- 🟢 **GOOD**: < 5 minutes (Green)
- 🟡 **ACCEPTABLE**: 5-15 minutes (Yellow)
- 🔴 **POOR**: > 15 minutes (Red)

**Shows:**
- Average MTTD
- 95th percentile (P95) MTTD
- Sample size (number of alerts analyzed)

**Why It Matters:**
- Faster detection = more time to respond
- High MTTD suggests rules are too complex or ES is lagging
- Industry best practice: < 5 minutes

---

### **4. MEAN TIME TO RESPOND (MTTR)**

**Display:** Metric card showing response efficiency
**Metric:** Time from alert to closure (in hours)

**Calculation:**
```
MTTR = resolved_at - alert.timestamp
Average across all CLOSED alerts in last 7 days
```

**Shows:**
- Average MTTR in hours
- Number of closed alerts
- Trend vs. previous week

**Why It Matters:**
- Measures analyst efficiency
- Higher = slower response = higher risk window
- Target: < 4 hours typical, < 2 hours for critical

---

### **5. MITRE ATT&CK COVERAGE HEATMAP**

**Display:** 11-cell heatmap showing all MITRE tactics
**Metric:** Number of distinct RULES covering each tactic

**Color Coding by Rule Coverage:**
- 🔴 **0 rules**: Dark Red - **BLIND SPOT** 
  - No detection capability for this tactic
  - Critical gap - adversaries use undetected
  
- 🟠 **1 rule**: Orange - LOW Coverage
  - Minimal detection coverage
  - Single rule failure = no visibility
  
- 🟡 **2-3 rules**: Yellow - MEDIUM Coverage
  - Reasonable coverage
  - Multiple detection paths

- 🟢 **4+ rules**: Green - GOOD Coverage
  - Strong detection capability
  - Redundancy if one rule fails

**The 11 MITRE Tactics:**
1. **Initial Access** - How attacker gets in
2. **Execution** - Running malicious code
3. **Persistence** - Maintaining access
4. **Privilege Escalation** - Getting higher rights
5. **Defense Evasion** - Hiding from detection
6. **Credential Access** - Stealing passwords
7. **Discovery** - Learning about the environment
8. **Lateral Movement** - Moving through network
9. **Collection** - Gathering data
10. **Exfiltration** - Stealing data out
11. **Impact** - Damaging systems/data

**Strategic Value:**
- Identify detection gaps in your rules
- Prioritize rule development
- Align with threat landscape

---

### **6. TOP THREATS FEED (Ranked by Urgency)**

**Display:** Ranked table of top 10 most urgent active alerts
**Ranking Formula:**
```
Urgency Score = (Severity_Weight × 3) + (Asset_Criticality_Weight × 2) + (Recency_Weight × 1)

Where:
- Severity: Critical=10, High=7, Medium=4, Low=2
- Asset Criticality: 0-10 based on asset risk_score
- Recency: Decays over time (10 to 0 over 100 minutes)
```

**Shows per Alert:**
- **Urgency Score**: Composite ranking (higher = more urgent)
- **Severity**: Color-coded badge (Critical/High/Medium/Low)
- **Rule Name**: Which detection rule fired
- **Source IP**: Attacking system
- **MITRE Tactic**: Attack classification
- **Timestamp**: When alert was generated
- **Investigate Button**: Quick link to incident details

**Why This Matters:**
- Critical alert from 2h ago on critical server > Low alert from 1 min ago on unknown box
- Analysts spend less time triaging with intelligent ranking
- Focuses effort on highest-impact threats

---

### **7. ALERT NOISE RATIO (False Positive Rate)**

**Display:** Metric card with noise level and recommendation
**Metric:** (False Positives closed this week) / (Total alerts closed this week) × 100

**Status Thresholds:**
- 🟢 **WELL-TUNED**: 0-15% (Green)
  - Rules are accurate
  - Recommendation: Maintain current tuning
  
- 🟡 **ACCEPTABLE**: 15-40% (Yellow)
  - Acceptable noise level
  - Monitor for improvement
  
- 🔴 **TOO NOISY**: > 40% (Red)
  - Rules need tuning
  - Recommendation: Adjust thresholds or exclude conditions

**How False Positives Detected:**
- Analyst closes alert with "False Positive" in resolution notes
- Automatically tracked and aggregated

**Why It Matters:**
- High FP rate = analyst fatigue = alerts ignored
- Directly impacts detection effectiveness
- Indicates rule quality issues

---

### **8. AUTO-REFRESH & TIMESTAMPS**

**Refresh Interval:** 60 seconds (1 minute)
- Automatic background update
- No manual refresh required
- Last updated timestamp shown bottom-right

**Update Sources:**
- Real-time WebSocket for new alerts
- Scheduled API polling for all metrics
- Cached results to reduce backend load

---

## 🔌 API Endpoints

### GET `/api/v1/dashboard/summary`

**Returns:** Complete dashboard data payload

```json
{
  "timestamp": "2024-10-15T14:30:45.123Z",
  "total_events_24h": 125420,
  "active_alerts": 47,
  "critical_count": 8,
  "high_count": 12,
  "assets_at_risk": 5,
  
  "security_posture": {
    "score": 72,
    "status": "fair",
    "color": "yellow",
    "details": {
      "critical_alerts": 8,
      "high_alerts": 12,
      "assets_at_risk": 5,
      "blind_spots": 3
    }
  },
  
  "alert_velocity": {
    "status": "spike_detected",
    "severity": "critical",
    "message": "🔴 ALERT SPIKE: 3.2x normal rate (48 alerts/hr vs 15.0 avg)",
    "current_rate": 48,
    "average_rate": 15.0,
    "ratio": 3.2
  },
  
  "mttd": {
    "average_mttd_minutes": 4.2,
    "p95_mttd_minutes": 8.5,
    "status": "good",
    "color": "green",
    "sample_size": 142
  },
  
  "mttr": {
    "average_mttr_hours": 2.3,
    "alerts_closed": 89,
    "sample_size": 89
  },
  
  "mitre_coverage": {
    "Initial Access": {"rule_count": 2, "color": "yellow", "label": "MEDIUM"},
    "Execution": {"rule_count": 1, "color": "orange", "label": "LOW"},
    "Persistence": {"rule_count": 0, "color": "dark_red", "label": "BLIND SPOT"},
    ...
  },
  
  "alert_noise_ratio": {
    "false_positive_ratio": 18.5,
    "total_closed_alerts": 200,
    "false_positives_count": 37,
    "status": "acceptable",
    "color": "yellow",
    "recommendation": "Monitor for improvement"
  },
  
  "top_threats": [
    {
      "alert_id": "ALT-a1b2c3d4",
      "rule_name": "Suspicious PowerShell Execution",
      "severity": "critical",
      "source_ip": "192.168.1.100",
      "entity": "ADMIN-PC",
      "mitre_tactic": "Execution",
      "timestamp": "2024-10-15T14:25:30.000Z",
      "urgency_score": 98.5,
      "status": "open"
    },
    ...
  ],
  
  "events_per_hour": [
    {"hour": "2024-10-15 00", "count": 4500},
    {"hour": "2024-10-15 01", "count": 3200},
    ...
  ]
}
```

---

## 🎨 Dashboard Layout

```
┌─────────────────────────────────────────────────────────────┐
│ SOC Dashboard                          Last updated: HH:MM:SS│
├─────────────────────────────────────────────────────────────┤
│                                                              │
│ ⚠️  ALERT SPIKE: 3.2x normal rate (when spike detected)     │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│           🟢 SECURITY POSTURE: 72/100 (FAIR)               │
│           Gauge visualization + breakdown                   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ MTTD 4m  │ │ MTTR 2h  │ │ Noise 18%│ │Alerts 47 │      │
│  │ GOOD     │ │ GOOD     │ │ OK       │ │ Medium   │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│ MITRE ATT&CK COVERAGE (11 Tactics)                          │
│  [IA]  [EX]  [PE]  [PR]  [DE]  [CA]  [DI]  [LM]  [CO] [...] │
│   2    1     4     2     0     3     1     2     5   ...   │
│   YEL  ORG  GRN   YEL  RED   YEL   ORG  YEL  GRN          │
├─────────────────────────────────────────────────────────────┤
│ EVENT VOLUME & ALERTS (24h)                                 │
│ [Line chart showing event volume]                           │
├─────────────────────────────────────────────────────────────┤
│ 🎯 TOP THREATS (Ranked by Urgency Score)                    │
│ ┌─────┬──────────┬─────────────┬──────────────┬─────────┐  │
│ │Score│Severity  │Rule Name    │Source IP     │ MITRE   │  │
│ ├─────┼──────────┼─────────────┼──────────────┼─────────┤  │
│ │98.5 │CRITICAL  │Suspicious   │192.168.1.100 │Execution│  │
│ │87.2 │HIGH      │Brute Force  │10.0.0.50     │Cred Acc │  │
│ │72.1 │MEDIUM    │Registry Mod │172.16.0.1    │Persist  │  │
│ └─────┴──────────┴─────────────┴──────────────┴─────────┘  │
│                                                              │
│ Dashboard refreshes every 60 seconds. Last: HH:MM:SS       │
└─────────────────────────────────────────────────────────────┘
```

---

## 💾 Data Sources

- **Elasticsearch**: siem-alerts-*, siem-logs-*
- **PostgreSQL**: Alert metadata, asset risk scores
- **Real-time**: WebSocket stream for new alerts

---

## 🚀 Performance Characteristics

- **Query Latency**: < 2 seconds typical
- **Refresh Rate**: 60-second interval
- **Data Retention**: 7-90 days (configurable)
- **Concurrent Dashboards**: Supports 100+ simultaneous viewers

---

## 🔧 Configuration

Backend environment variables:
```env
ELASTICSEARCH_HOSTS=http://elasticsearch:9200
DASHBOARD_REFRESH_INTERVAL=60  # seconds
ALERT_SPIKE_THRESHOLD=2.0      # multiplier of average
QUIET_THRESHOLD=0.1            # multiplier of average
DEAD_RULE_DAYS=7               # days to check
```

---

## 📊 Recommended Alert Tuning

Based on dashboard metrics:

| Metric | Recommendation | Action |
|--------|---|---|
| MTTD > 15m | Rules too complex | Simplify rule logic |
| MTTR > 8h | Analyst bottleneck | Add staffing/training |
| Noise > 40% | Rules too broad | Add conditions/thresholds |
| Coverage = 0 | Blind spot | Create new detection rule |
| Spike detected | Possible attack | Activate incident response |

---

## 📈 Real-World Usage Examples

### Scenario 1: Ransomware Attack Detected
```
1. Alert spike banner appears: 5.2x normal rate
2. Security Posture drops from 78 → 45 (CRITICAL)
3. Multiple HIGH/CRITICAL alerts in Top Threats
4. Urgency scores > 90 for ransom-related rules
5. Analyst sees immediate severity + context
→ Initiates incident response playbook
```

### Scenario 2: Sensor Failure
```
1. Alert Velocity banner: "UNUSUALLY QUIET - 0.05x normal"
2. Check agent connectivity
3. Discover Syslog collector offline
4. Restart service
5. Alerts resume normal rate
→ Prevented undetected lateral movement
```

### Scenario 3: Rule Tuning
```
1. Notice Noise Ratio: 52% (too high)
2. Check which rules causing FPs in Top Threats
3. Find "Privilege Escalation" rule too sensitive
4. Adjust thresholds or add exclusions
5. Retest, validate noise drops to 18%
→ Improves rule quality long-term
```

---

## 🎓 Key Takeaways

✅ **Security Posture Score** = At-a-glance health check  
✅ **Alert Velocity** = Detect attacks AND sensor failures  
✅ **MTTD/MTTR** = Measure detection & response efficiency  
✅ **MITRE Coverage** = Identify blind spots proactively  
✅ **Top Threats Ranking** = Intelligent triage saves time  
✅ **Noise Ratio** = Guide rule tuning efforts  
✅ **Auto-refresh** = Always current without manual work  

This dashboard transforms raw alert streams into **actionable security intelligence**.
