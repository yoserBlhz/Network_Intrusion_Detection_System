# ML-Based Rule Generation System

## Overview

The ML-Based Rule Generation System enhances the Network Intrusion Detection System (NIDS) by automatically generating and tuning detection rules using machine learning analysis of historical network data. This system provides intelligent, data-driven rule creation that adapts to network patterns and improves detection accuracy over time.

## Key Features

### 1. **Automated Rule Generation**
- **Protocol Anomaly Rules**: Detects unusual patterns in protocol usage
- **Port Anomaly Rules**: Identifies suspicious port activity
- **Temporal Rules**: Recognizes time-based anomalies
- **Behavioral Rules**: Monitors source IP behavior patterns

### 2. **Machine Learning Techniques**
- **Isolation Forest**: Detects anomalous patterns in network flows
- **K-Means Clustering**: Groups similar flows for pattern analysis
- **Statistical Analysis**: Calculates thresholds based on historical data
- **Feature Engineering**: Extracts meaningful features from flow data

### 3. **Rule Management**
- **Rule Storage**: JSON-based rule persistence
- **Rule Filtering**: Filter by type, severity, and confidence
- **Rule Statistics**: Comprehensive analytics and reporting
- **Rule Application**: Real-time application to live network flows

## Architecture

### Core Components

#### 1. **MLRuleGenerator Class** (`utils/ml_rule_generator.py`)
```python
class MLRuleGenerator:
    def __init__(self, db_path: str = "nids.db"):
        self.db_path = db_path
        self.rules_file = "ml_generated_rules.json"
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
```

**Key Methods:**
- `analyze_historical_data(hours)`: Main analysis function
- `generate_protocol_rules(flows_data)`: Protocol-based rule generation
- `generate_port_rules(flows_data)`: Port-based rule generation
- `generate_temporal_rules(flows_data)`: Time-based rule generation
- `generate_behavioral_rules(flows_data)`: Behavioral pattern rules
- `apply_ml_rules(flow_data)`: Apply rules to individual flows

#### 2. **Feature Extraction**
```python
def extract_features_from_flows(self, flows_data: List[Dict]) -> pd.DataFrame:
    # Extracts features like:
    # - flow_duration
    # - packets_per_second
    # - bytes_per_packet
    # - protocol_numeric
    # - port_numeric
    # - direction indicators
    # - time-based features
```

#### 3. **Anomaly Detection**
```python
def detect_anomalous_patterns(self, features_df: pd.DataFrame) -> Dict[str, Any]:
    # Uses Isolation Forest to detect anomalies
    # Returns anomaly statistics and patterns
```

### 4. **Rule Types**

#### Protocol Anomaly Rules
- **Purpose**: Detect unusual protocol usage patterns
- **Features**: Packet count, byte count, unique destinations
- **Thresholds**: Mean + 2*Standard Deviation
- **Example**: "TCP flows with >1000 packets in 1 hour"

#### Port Anomaly Rules
- **Purpose**: Identify suspicious port activity
- **Features**: Port-specific traffic patterns
- **Severity**: Based on port risk level (SSH=HIGH, HTTP=MEDIUM)
- **Example**: "Port 22 with >500 packets from single source"

#### Temporal Anomaly Rules
- **Purpose**: Detect time-based anomalies
- **Features**: Hourly traffic baselines
- **Thresholds**: Baseline + 50% for anomaly
- **Example**: "Unusual traffic spike at 2:00 AM"

#### Behavioral Anomaly Rules
- **Purpose**: Monitor source IP behavior patterns
- **Features**: IP-specific traffic characteristics
- **Detection**: Statistical outliers in behavior
- **Example**: "IP 192.168.1.100 with >10 unique destinations"

## API Endpoints

### Rule Generation
```http
GET /api/ml/generate_rules?hours=24
```
Generates ML rules from historical data.

### Rule Management
```http
GET /api/ml/rules
GET /api/ml/rules/{rule_type}
GET /api/ml/rule_statistics
DELETE /api/ml/delete_rules
```

### Rule Application
```http
GET /api/ml/apply_rules
```
Applies ML rules to current live flows.

## Web Interface

### ML Rules Page (`/ml_rules`)
- **Rule Statistics Dashboard**: Overview of generated rules
- **Rule Generation Controls**: Configure and trigger rule generation
- **Analysis Results**: Detailed analysis output
- **Rules Table**: View and filter generated rules

### Features:
- Real-time rule statistics
- Configurable analysis periods (6-72 hours)
- Rule type filtering
- Confidence score visualization
- Rule management actions

## Integration with Existing System

### Enhanced Suspicious Flow Detection
The ML rules are integrated into the existing `detect_suspicious_flows()` method:

```python
def detect_suspicious_flows(self, df: pd.DataFrame) -> pd.DataFrame:
    # Existing rule-based detection
    # + ML-generated rules
    ml_triggers = self.ml_rule_generator.apply_ml_rules(flow_dict)
```

### Structured Alerts
ML rule triggers are included in structured alerts:
- **ML Rule Count**: Number of ML rules triggered
- **ML Triggered Rules**: Details of triggered rules
- **Enhanced Suspicion Reasons**: Combined rule-based and ML-based reasons

## Usage Examples

### 1. Generate Rules from Historical Data
```python
from utils.ml_rule_generator import MLRuleGenerator

# Initialize generator
ml_generator = MLRuleGenerator()

# Generate rules from last 24 hours
analysis_result = ml_generator.analyze_historical_data(hours=24)

# Access generated rules
rules = analysis_result['rules']
print(f"Generated {len(rules)} rules")
```

### 2. Apply Rules to Live Flows
```python
# Get live flows
live_flows = get_live_flows(window=60)

# Apply ML rules
for flow in live_flows:
    triggers = ml_generator.apply_ml_rules(flow)
    if triggers:
        print(f"Flow triggered {len(triggers)} ML rules")
```

### 3. Web Interface Usage
1. Navigate to `/ml_rules`
2. Select analysis period (e.g., 24 hours)
3. Click "Generate Rules"
4. View analysis results and generated rules
5. Apply rules to live flows
6. Monitor rule effectiveness

## Configuration

### Rule Generation Parameters
```python
# Isolation Forest parameters
contamination = 0.1  # Expected proportion of anomalies
random_state = 42    # For reproducible results

# Clustering parameters
n_clusters = 5       # Number of clusters for pattern analysis

# Threshold calculations
packet_threshold = packet_mean + (2 * packet_std)  # 2-sigma rule
byte_threshold = byte_mean + (2 * byte_std)
```

### Severity Mapping
```python
def _determine_port_severity(self, port: int) -> str:
    high_risk_ports = {22, 23, 3389, 445, 135, 139, 1433, 3306, 5432}
    medium_risk_ports = {21, 25, 53, 80, 110, 143, 443, 993, 995}
    
    if port in high_risk_ports:
        return 'HIGH'
    elif port in medium_risk_ports:
        return 'MEDIUM'
    else:
        return 'LOW'
```

## Benefits

### 1. **Adaptive Detection**
- Rules automatically adapt to network patterns
- Reduces false positives through statistical analysis
- Improves detection accuracy over time

### 2. **Comprehensive Coverage**
- Multiple rule types cover different attack vectors
- Temporal analysis detects time-based attacks
- Behavioral analysis identifies compromised hosts

### 3. **Scalable Architecture**
- JSON-based rule storage for easy management
- RESTful API for integration
- Web interface for user-friendly management

### 4. **Real-time Application**
- Rules applied to live network flows
- Immediate detection of new threats
- Integration with existing alert system

## Testing

### Test Script
Run the test script to verify functionality:
```bash
python test_ml_rules.py
```

### Test Coverage
- Rule generation from historical data
- Rule statistics and management
- Rule application to live flows
- Integration with network analysis
- Web interface functionality

## Future Enhancements

### 1. **Advanced ML Models**
- Deep learning for pattern recognition
- Reinforcement learning for rule optimization
- Ensemble methods for improved accuracy

### 2. **Rule Optimization**
- Automatic rule tuning based on performance
- Rule conflict resolution
- Confidence score calibration

### 3. **Enhanced Features**
- Network topology awareness
- User behavior analysis
- Threat intelligence integration

### 4. **Performance Improvements**
- Parallel rule processing
- Caching for frequently used rules
- Optimized feature extraction

## Conclusion

The ML-Based Rule Generation System significantly enhances the NIDS by providing intelligent, data-driven detection capabilities. By combining traditional rule-based detection with machine learning analysis, the system offers:

- **Improved Detection Accuracy**: Statistical analysis reduces false positives
- **Adaptive Capabilities**: Rules evolve with network patterns
- **Comprehensive Coverage**: Multiple detection approaches
- **User-Friendly Management**: Web interface for easy operation
- **Real-time Application**: Immediate threat detection

This system represents a significant advancement in network security, providing automated, intelligent threat detection that adapts to the specific characteristics of each network environment. 