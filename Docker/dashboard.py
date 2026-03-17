import os
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
from sklearn.metrics import classification_report
from datetime import datetime

# # DEBUG: Affiche le répertoire courant
# st.write("Current directory:", os.getcwd())
# st.write("Files in current directory:", os.listdir('.'))

# # Vérifie que les fichiers existent
# files_to_check = ['best_banana_brain.keras', 'banana_scaler.pkl', 'expected_columns.pkl']
# for f in files_to_check:
#     exists = os.path.exists(f)
#     st.write(f"{f}: {'✅ EXISTS' if exists else '❌ MISSING'}")

def align_columns(df, expected_columns):
    """
    Aligne les colonnes du CSV uploadé avec celles attendues par le modèle.
    - Supprime les colonnes en trop
    - Ajoute les colonnes manquantes avec des 0
    - Réordonne dans le bon ordre
    """
    # Supprime les colonnes inutiles (metadata, labels)
    cols_to_drop = ['Unnamed: 0', 'Flow ID', ' Source IP', ' Source Port', 
                    ' Destination IP', ' Destination Port', ' Protocol', 
                    ' Timestamp', ' Label', 'Label', ' Inbound', 'SimillarHTTP']
    df = df.drop(columns=cols_to_drop, errors='ignore')
    
    current_cols = set(df.columns)
    expected_cols = set(expected_columns)
    
    # Colonnes manquantes → ajouter avec 0
    missing_cols = expected_cols - current_cols
    for col in missing_cols:
        df[col] = 0
    
    # Colonnes en trop → supprimer
    extra_cols = current_cols - expected_cols
    df = df.drop(columns=list(extra_cols), errors='ignore')
    
    # Réordonner selon l'ordre attendu
    df = df[expected_columns]
    
    return df

# Configuration de la page
st.set_page_config(
    page_title="Network IDS",
    page_icon="🛡️",
    layout="wide"
)

# Chargement du modèle et scaler
@st.cache_resource
def load_model_and_scaler_expected_columns():
    model = tf.keras.models.load_model('best_banana_brain.keras')
    scaler = joblib.load('banana_scaler.pkl')
    expected_columns = joblib.load('expected_columns.pkl')
    return model, scaler, expected_columns

try:
    model, scaler, expected_columns = load_model_and_scaler_expected_columns()
    model_loaded = True
except Exception as e:
    st.error(f"Error loading model: {e}")
    model_loaded = False

# Header
st.title("🛡️ AI-Powered Network Intrusion Detection System (AINIDSystem)")
st.markdown("Real-time network traffic analysis using Deep Learning")

# Sidebar - Statistics
st.sidebar.header("📊 System Statistics")
if 'total_flows' not in st.session_state:
    st.session_state.total_flows = 0
    st.session_state.attacks_detected = 0

st.sidebar.metric("Total Flows Analyzed", st.session_state.total_flows)
st.sidebar.metric("Attacks Detected", st.session_state.attacks_detected)
if st.session_state.total_flows > 0:
    detection_rate = (st.session_state.attacks_detected / st.session_state.total_flows) * 100
    st.sidebar.metric("Attack Rate", f"{detection_rate:.2f}%")

st.sidebar.markdown("---")
st.sidebar.info("Upload a CSV file with network flow features to analyze")

# Main content
if not model_loaded:
    st.warning("⚠️ Model not loaded. Please check the PATH of 'intrusion_detection_final.keras' and 'scaler_final.pkl' are CORRECT.")
    st.stop()

# File upload
st.header("📁 Upload Network Flow Data")
uploaded_file = st.file_uploader(
    "Choose a CSV file containing network flow features",
    type="csv",
    help="Upload a CSV file with the same 78 features used during training"
)

if uploaded_file is not None:
    try:
        # Load data
        df = pd.read_csv(uploaded_file)
        st.success(f"✅ Loaded {len(df)} network flows")
        
        # Show preview
        with st.expander("📋 View Data Preview"):
            st.dataframe(df.head(10))
        
        # Preprocess
        with st.spinner("🔄 Processing data..."):
            true_label_series = None
            if ' Label' in df.columns:
                true_label_series = (df[' Label'] != 'BENIGN').astype(int).map({0: 'BENIGN', 1: 'ATTACK'})
            elif 'Label' in df.columns:
                true_label_series = (df['Label'] != 'BENIGN').astype(int).map({0: 'BENIGN', 1: 'ATTACK'})
            
            st.write("DEBUG - true_label_series créé?", true_label_series is not None)  # DEBUG
            
            # PUIS align
            df = align_columns(df, expected_columns)
            
            # PUIS rajoute APRÈS
            if true_label_series is not None:
                df['True_Label'] = true_label_series.values  # Utilise .values pour être sûr
                st.write("DEBUG - True_Label ajouté, sample:", df['True_Label'].head())  # DEBUG
            
            # Remove label column if exists
            X = df.drop(columns=[' Label', 'Label', 'True_Label'], errors='ignore')
            
            # Convert to numeric
            X = X.apply(pd.to_numeric, errors='coerce')
            
            # Handle missing values
            X = X.fillna(0)
            
            # Replace inf values
            X.replace([np.inf, -np.inf], 0, inplace=True)
            
            # Scale
            X_scaled = scaler.transform(X)
            
            # Predict
            predictions_proba = model.predict(X_scaled, verbose=0)
            predictions = (predictions_proba > 0.8).astype(int).flatten()
            
            # Add results to dataframe
            df['Prediction'] = predictions
            df['Confidence'] = predictions_proba.flatten()
            df['Status'] = df['Prediction'].map({0: 'BENIGN', 1: 'ATTACK'})
        
        # Update statistics
        st.session_state.total_flows += len(df)
        st.session_state.attacks_detected += (predictions == 1).sum()
        
        # Display results
        st.header("📊 Detection Results")
        
        # DEBUG
        # st.write("DEBUG - Colonnes dans df:", df.columns.tolist())
        # st.write("DEBUG - 'True_Label' présent?", 'True_Label' in df.columns)

        
        # Performance metrics (si True_Label existe)
        if 'True_Label' in df.columns:
            st.subheader("🎯 Model Performance on This File")
            
            report = classification_report(
                df['True_Label'], 
                df['Status'], 
                output_dict=True
            )
            
            perf_col1, perf_col2, perf_col3 = st.columns(3)
            with perf_col1:
                st.metric("✅ Accuracy", f"{report['accuracy']:.1%}")
            with perf_col2:
                st.metric("📈 Attack Recall", f"{report['ATTACK']['recall']:.1%}")
            with perf_col3:
                st.metric("🎯 Attack Precision", f"{report['ATTACK']['precision']:.1%}")
        
        # Statistiques générales (toujours affichées)
        st.subheader("Prediction Summary")
        
        col1, col2, col3 = st.columns(3)
        
        benign_count = (predictions == 0).sum()
        attack_count = (predictions == 1).sum()
        
        with col1:
            st.metric("Benign Flows", benign_count, delta=f"{(benign_count/len(df)*100):.1f}%")
        
        with col2:
            st.metric("Attack Flows", attack_count, delta=f"{(attack_count/len(df)*100):.1f}%")
        
        with col3:
            avg_confidence = df['Confidence'].mean()
            st.metric("Average Confidence", f"{avg_confidence:.2%}")
        
        # Show attacks
        attacks = df[df['Prediction'] == 1].copy()
        
        if len(attacks) > 0:
            st.subheader("🚨 Detected Attacks")
            st.markdown(f"**{len(attacks)} suspicious flows detected**")
            
            # Sort by confidence
            attacks_sorted = attacks.sort_values('Confidence', ascending=False)
            
            # Display top attacks
            display_cols = ['Status', 'Confidence']
            # Add some feature columns if they exist
            feature_cols = [col for col in df.columns if col not in ['Prediction', 'Status', 'Confidence', ' Label', 'Label']]
            if len(feature_cols) > 0:
                display_cols.extend(feature_cols[:5])  # Show first 5 features
            
            st.dataframe(
                attacks_sorted[display_cols].head(20),
                use_container_width=True
            )
            
            # Confidence distribution
            st.subheader("📈 Attack Confidence Distribution")
            st.bar_chart(attacks['Confidence'].value_counts().sort_index())
        else:
            st.success("✅ No attacks detected! All traffic appears benign.")
        
        # Download results
        st.header("💾 Download Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Full results
            csv_full = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Full Results (CSV)",
                data=csv_full,
                file_name=f"intrusion_detection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        with col2:
            # Attacks only
            if len(attacks) > 0:
                csv_attacks = attacks.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="🚨 Download Attacks Only (CSV)",
                    data=csv_attacks,
                    file_name=f"detected_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            
    except Exception as e:
        st.error(f"❌ Error processing file: {str(e)}")
        st.exception(e)

else:
    st.info("👆 Upload a CSV file to start analyzing network traffic")
    
    # Instructions
    with st.expander("ℹ️ How to use"):
        st.markdown("""
        1. **Prepare your data**: CSV file with 78 network flow features (same as training data)
        2. **Upload**: Click the upload button above
        3. **Analyze**: The system will automatically detect attacks
        4. **Download**: Export results for further analysis
        
        **Expected columns**: Flow Duration, Total Fwd Packets, Total Backward Packets, etc.
        """)

# Footer
st.markdown("---")
st.markdown("*Powered by TensorFlow & Streamlit | 98% Accuracy | 97% Attack Detection Rate*")