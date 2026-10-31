# Detection Quality Review

## Verified counts
Total detections: 258
Unique source events: 237
Events matched by multiple rules: 21
Duplicate same rule/source: 0

## Rule counts
AUTH-001 147
NET-001 44
IPS-001 27
IPS-002 21
AV-001 13
WEB-001 6

## Category/severity
authentication medium 147
intrusion_prevention critical 21 (IPS-002)
intrusion_prevention high 27 (IPS-001)
malware high 13
network_traffic low 44
web_filtering medium 6

## Source integrity
All 258 detection source references resolve to original parsed events (0 unresolved).

## Auth
147 detections match 147 original failed login events.

## Malware
13 detections match 13 original virus events.

## Severity mapping confirmed
IPS-001 -> high (27)
IPS-002 -> critical (21)

## SQL Validation Evidence

### Total detections

```sql
SELECT count(*) AS total_detections FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet')
```

Output:
```

(258,)
```

### Unique source events

```sql
SELECT count(DISTINCT (source_file||':'||cast(line_number AS VARCHAR))) AS unique_events FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet')
```

Output:
```

(237,)
```

### Events matched by multiple rules

```sql
SELECT count(*) AS multi_rule_events FROM (SELECT source_file,line_number FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet') GROUP BY 1,2 HAVING count(DISTINCT rule_id)>1)
```

Output:
```

(21,)
```

### Duplicate same rule/source

```sql
SELECT count(*) AS duplicate_rule_events FROM (SELECT rule_id,source_file,line_number FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet') GROUP BY 1,2,3 HAVING count(*)>1)
```

Output:
```

(0,)
```

### Multi-rule match examples

```sql
SELECT source_file,line_number,count(DISTINCT rule_id) AS n_rules,string_agg(DISTINCT rule_id, ', ') AS rules FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet') GROUP BY 1,2 HAVING count(DISTINCT rule_id)>1 ORDER BY n_rules DESC LIMIT 10
```

Output:
```

('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 787, 2, 'IPS-001, IPS-002')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 755, 2, 'IPS-002, IPS-001')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 606, 2, 'IPS-001, IPS-002')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 176, 2, 'IPS-001, IPS-002')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 648, 2, 'IPS-001, IPS-002')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 697, 2, 'IPS-001, IPS-002')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 325, 2, 'IPS-002, IPS-001')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 607, 2, 'IPS-002, IPS-001')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 230, 2, 'IPS-001, IPS-002')
('C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log', 528, 2, 'IPS-002, IPS-001')
```

### Duplicate same rule/source details

```sql
SELECT source_file,line_number,rule_id,count(*) AS dup_count FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet') GROUP BY 1,2,3 HAVING count(*)>1
```

Output:
```

```

### IPS severity mapping

```sql
SELECT rule_id,severity,count(*) AS n FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet') WHERE category='intrusion_prevention' GROUP BY 1,2 ORDER BY 1,2
```

Output:
```

('IPS-001', 'high', 27)
('IPS-002', 'critical', 21)
```

### Source reference validation

```sql
SELECT count(*) AS total, count(o.line_number) AS valid, count(*)-count(o.line_number) AS unresolved FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet') d LEFT JOIN read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/sample1000.parquet') o ON d.source_file=o.source_file AND d.line_number=o.line_number
```

Output:
```

(258, 258, 0)
```

### Original failed logins

```sql
SELECT count(*) AS original_failed_logins FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/sample1000.parquet') WHERE type='event' AND subtype='system' AND json_extract_string(fields_json,'$.action')='login' AND json_extract_string(fields_json,'$.status')='failed'
```

Output:
```

(147,)
```

### Auth detections

```sql
SELECT count(*) AS auth_detections FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet') WHERE rule_id='AUTH-001'
```

Output:
```

(147,)
```

### Original virus records

```sql
SELECT count(*) AS original_virus FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/sample1000.parquet') WHERE type='utm' AND subtype='virus'
```

Output:
```

(13,)
```

### Malware detections

```sql
SELECT count(*) AS malware_detections FROM read_parquet('C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet') WHERE rule_id='AV-001'
```

Output:
```

(13,)
```
