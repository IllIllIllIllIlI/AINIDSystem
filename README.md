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

## License

MIT
