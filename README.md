# AI-Powered Network Intrusion Detection System

Deep Learning model for real-time network attack detection with 91% accuracy.

## Quick Start

### Run with Docker
```bash
docker pull yourname/ainidsystem
docker run -p 8501:8501 yourname/ainidsystem
```

Access dashboard at `http://localhost:8501`

### Run locally
```bash
cd app
pip install -r requirements.txt
streamlit run dashboard.py
```

## Performance

- **Accuracy**: 91%
- **Attack Recall**: 91%  
- **Attack Precision**: 71%
- **Dataset**: CICIDS2017 (2.8M flows)

## Architecture

- **Model**: Deep Neural Network (TensorFlow)
- **Dashboard**: Streamlit
- **Deployment**: Docker

## Project Structure
```
├── app/              # Streamlit dashboard
├── brAIn/            # Trained models
├── data/             # Training data
├── Docker/           # Docker configuration
└── notebook/         # Jupyter notebooks
```

##  Tech Stack

- TensorFlow
- Streamlit
- scikit-learn
- Docker


## Technical Challenges & Lessons Learned


### The Idea & Its Application


I wanted to create an automated system that could analyze network packets captured with Wireshark and classify them as benign or malicious attacks. 
The goal was to integrate this as both an API and a Docker-deployable solution.
Initially, I planned to work directly with .pcap files. 
However, after consulting with man's new bestfriend, after the dog, Claude AI and researching available datasets, I pivoted to CSV format for better accessibility and easier model training. 
I found the Canadian Institute for Cybersecurity's CICIDS2017 dataset, which provided comprehensive, well-organized network flow data with 78 features per flow.
The main technical challenge emerged when attempting to convert .pcap files to CSV format using CICFlowMeter. 
The tool proved deprecated and incompatible with modern systems, requiring extensive debugging that would have derailed the project timeline.
Rather than abandon the work, I adapted the approach: I built a Streamlit dashboard that directly processes pre-formatted CSV files, allowing security analysts to upload network flow data and receive real-time predictions. 
While this differs from my original vision of a fully automated packet-capture pipeline, the resulting system successfully demonstrates:

A deep neural network achieving 91% attack detection accuracy
Real-time inference on network flow data
Docker deployment for portability
A functional proof-of-concept for ML-based intrusion detection

The project taught me valuable lessons about adapting scope when faced with technical constraints and delivering working solutions over perfect implementations. 
While packet capture automation remains a future enhancement, the core ML pipeline is production-ready and deployable.

  
## System Requirements

**Development Environment:**
- GPU: NVIDIA RTX 4060 (8GB VRAM)
- Training time: ~30 minutes on full dataset
- Inference: Works on CPU (no GPU required)

**Minimum Requirements:**
- Python 3.10+
- 8GB RAM
- Docker (optional)


## License

MIT
