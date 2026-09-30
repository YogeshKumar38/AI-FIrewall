# AI Firewall

### A Semantic Security Layer for LLM Applications

AI Firewall is a security-focused application that analyzes user prompts before forwarding them to a Large Language Model (LLM). It combines rule-based detection, a fine-tuned DeBERTa semantic model, contextual intent analysis, semantic retrieval, and risk-based policy decisions.

The application provides an interactive **Streamlit interface** and uses the **Gemini API** to generate responses for prompts permitted by the security policy.

---

## Project Overview

AI Firewall aims to provide a structured security layer between users and an LLM.

### Key Features

- Semantic prompt-injection detection using DeBERTa.
- Rule-based detection of suspicious prompt patterns.
- Contextual intent analysis and semantic retrieval.
- Risk scoring and policy-based decisions.
- Three security actions: `ALLOW`, `REVIEW`, and `BLOCK`.
- Gemini API integration for permitted prompts.
- Streamlit interface for prompt submission and result visualization.

---

## Architecture

```text
                User
                 |
                 v
          Streamlit UI
                 |
                 v
          User Prompt
                 |
                 v
       Preprocessing & Normalization
                 |
                 v
        Security Rule Engine
                 |
                 v
      DeBERTa Semantic Detector
                 |
                 v
          Intent Analyzer
                 |
                 v
        Semantic Retrieval
                 |
                 v
            Risk Engine
                 |
                 v
           Policy Engine
                 |
                 v
       Security Decision
                 |
         +-------+-------+
         |       |       |
         v       v       v
       ALLOW   REVIEW   BLOCK
         |
         v
      Gemini API
         |
         v
    LLM Response
         |
         v
     Streamlit UI
         |
         v
        User
```

### Pipeline Components

| Component | Responsibility |
|---|---|
| Streamlit UI | Accepts user prompts and displays security results and responses |
| Preprocessing | Normalizes input prompts |
| Security Rule Engine | Detects known patterns and security signals |
| DeBERTa Semantic Detector | Classifies prompts using learned semantic representations |
| Intent Analyzer | Adds contextual intent evidence |
| Semantic Retriever | Retrieves related security evidence |
| Risk Engine | Combines signals and determines risk |
| Policy Engine | Maps risk levels to `ALLOW`, `REVIEW`, or `BLOCK` |
| Gemini API | Generates responses for prompts permitted by the configured policy |

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application and pipeline |
| Streamlit | Interactive frontend |
| PyTorch | Deep learning model execution |
| Hugging Face Transformers | Transformer model training and inference |
| DeBERTa-v3 | Semantic prompt classification |
| Sentence Transformers / E5 | Semantic embeddings and retrieval |
| FAISS | Vector similarity search |
| Scikit-learn | Data processing and evaluation metrics |
| Gemini API | LLM response generation |
| Pytest | Automated testing |
| Git and GitHub | Version control |

---

## Datasets

The model development workflow uses three public prompt-injection datasets.

| Dataset | Description |
|---|---|
| [S-Labs Prompt Injection Dataset](https://huggingface.co/datasets/S-Labs/prompt-injection-dataset) | Prompt-injection examples |
| [Neuralchemy Full Dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset) | Full prompt-injection dataset |
| [Neuralchemy Categorized Binary Dataset](https://huggingface.co/datasets/neuralchemy/prompt-injection-dataset-categorized) | Categorized binary prompt examples |

The datasets were normalized and combined into a common format, followed by preprocessing and contamination checks to reduce duplicate and overlapping examples.

The notebook reports **63,530 combined normalized rows** across the three source datasets before later cleaning and splitting.

Dataset licenses and attribution requirements should be checked before redistribution.

---

## Model Performance

### First Model — Held-Out Test Results

The first model's evaluation was performed on an untouched test set of **5,492 samples**.

| Metric | Score |
|---|---:|
| Accuracy | **97.01%** |
| Precision | **98.81%** |
| Recall | **96.52%** |
| F1-score | **97.65%** |
| ROC-AUC | **99.46%** |
| PR-AUC | **99.72%** |

### Confusion Matrix

| | Predicted Benign | Predicted Malicious |
|---|---:|---:|
| Actual Benign | 1,918 | 41 |
| Actual Malicious | 123 | 3,410 |

These results represent the model's performance on the specified held-out dataset. They do not guarantee equivalent performance on real-world prompts or adversarial attacks.

---

## Security Decisions

| Decision | Meaning |
|---|---|
| `ALLOW` | Prompt is permitted to proceed to the Gemini API |
| `REVIEW` | Prompt requires additional handling or review |
| `BLOCK` | Prompt is prevented from reaching the LLM |

The active risk-to-action mapping is controlled by the security policy configuration.

---

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/YogeshKumar38/AI-FIrewall.git
cd AI-FIrewall
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Configure the Gemini API

Add your Gemini API key to your local environment configuration. Never commit API keys or other credentials to GitHub.

### 5. Run the application

```powershell
streamlit run app/streamlit_app.py
```

Check the application's entry-point file if your Streamlit frontend is located elsewhere.

---

## Testing

Run the automated test suite:

```powershell
python -m pytest -v
```

**Latest test result:** 26 tests passed, including 24 firewall cases and 2 adversarial tests.

---

## Future Scope

- Improve semantic understanding of subtle and indirect attacks.
- Strengthen contextual intent analysis and multi-turn security.
- Expand adversarial and semantic challenge datasets.
- Improve risk calibration and reduce false positives and false negatives.
- Evaluate the complete Streamlit-to-Gemini workflow.
- Improve model reproducibility and deployment.
- Expand security policy customization and monitoring.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

The license applies to the project code and does not automatically cover third-party datasets, models, or dependencies.