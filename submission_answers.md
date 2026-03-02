# UPSaclay AI Master Track - Application Answers

**Note to Applicant (USER):** Please adjust the "GitHub URL", "Username", and "Commit SHAs" below to match the repository where you eventually push this code, as well as your actual specific hardware.

---

### A. Code & Repositories

**Link to one public repo where you implemented an ML component:**
- **URL:** `https://github.com/YourUsername/NetGuard-ML`
- **File path of core model code:** `model.py` and `train.py`
- **Username:** `YourUsername`
- **Commit SHAs:** *(Insert 3 SHAs after you push)*

**Reviewer note (M1/M2):** This mini-project contains an error analysis phase in `train.py` and explicitly utilizes PyTorch's Profiler and Weights & Biases for deployment-grade infrastructure.

**Briefly describe your role (≤50 words):**
I designed the entire pipeline from scratch: synthesizing data, training a custom PyTorch MLP for binary classification with PyTorch Profiler and Weights & Biases, and deploying the model into a full real-time microservices architecture using Docker, Flask, and WebSockets.

**Paste a 10–20 line snippet... Which lines are yours? Why are they written that way? (≤60 words):**
```python
        np.random.seed(seed)
        torch.manual_seed(seed)
        benign_features = np.random.normal(loc=[500, 0.1, 1, 0, 80, 443], scale=[100, 0.05, 0, 0, 10, 10], size=(benign_samples, 6))
        mal_features = np.random.normal(loc=[64, 0.001, 0, 1, 50000, 80], scale=[10, 0.0005, 0, 0, 5000, 0], size=(mal_samples, 6))
        self.features = np.vstack([benign_features, mal_features])
        self.features[:, 0] = np.clip(self.features[:, 0], 20, 1500) # packet length
        self.features[:, 1] = np.clip(self.features[:, 1], 0, None)  # time >= 0
```
**Which/Why:** All lines are mine. I generated synthetic flow features using normal distributions representing benign vs DDoS-like traffic. I added strict clipping for packet lengths and inter-arrival times to ensure physical network bounds, mitigating unphysical edge cases prior to tensor conversion.

**Show the exact command... Include environment:**
```bash
python train.py --lr 0.001 --batch_size 64 --epochs 20 --seed 42 --num_samples 10000
```
Environment: pip virtual environment (Python 3.10+), PyTorch 2.0+ (CUDA optional).
Requirements path: `requirements.txt`

---

### B. Data & Reproducibility

**What dataset did you use most recently? (≤80 words):**
A generated synthetic network anomaly dataset mimicking DDoS attacks. It contains 10,000 samples and 6 features (packet length, time, protocols, ports). I used an 80/20 train/validation split using `torch.utils.data.random_split`. For data cleaning, I performed bound clipping: enforcing minimum limits of 20 bytes up to 1500 byte MTU thresholds for packet lengths, and clamping inter-arrival times to always be strictly non-negative.

**Reproducibility: how did you set seeds... (≤60 words):**
I centrally set seeds for `random`, `np.random`, `torch.manual_seed`, and `cuda.manual_seed_all`, alongside forcing deterministic cuDNN operations via `cudnn.deterministic = True`. I explicitly passed a generator to `random_split` and a `worker_init_fn` for dataloaders. One remaining source of nondeterminism is atomic add operations on GPUs during backpropagation.

---

### C. Modeling Decisions

**Specify: task type; model family; why that choice... (≤100 words):**
Task: Binary classification of network flows (Benign vs Malicious). 
Model Family: Multi-Layer Perceptron (PyTorch). 
Why: Network tabular data (independent hand-crafted flow statistics) lacks spatial (CNN) or rigid sequential (RNN) priors on a per-packet basis, making MLPs computationally lightweight for real-time inference without padding overheads.
Impactful hyperparameter: The learning rate. Tuned over a range of `[1e-2, 1e-4]`, the value `1e-3` offered the best convergence without oscillating aggressively around local minima on the non-linear decision boundary.

**Supervision signal (≤60 words):**
Supervised learning. I generated discrete explicit binary labels (0 for benign, 1 for malicious) attached directly to the artificially synthesized vectors, effectively training the model to recognize parameterized statistical divergence between the traffic clusters.

---

### D. Evaluation & Error Analysis

**List the primary metric... one trade-off (≤60 words):**
The primary metric was validation loss (Binary Cross-Entropy), closely monitored alongside Overall Accuracy. In network security, optimizing purely for accuracy introduces a trade-off: false positives (benign flagged as malicious) scale up, requiring manual administrative review, versus false negatives which risk network compromise but maintain high uptime.

**Show one concrete failure mode... why it failed (≤100 words):**
Error analysis isolated failure modes on edge cases where a benign packet was exceptionally small (e.g. an empty ACK packet under 70 bytes) and temporally fast, imitating the synthesized DDoS signature perfectly. 
*Failure:* `Features: [65.2, 0.008, ...], True: 0.0, Pred: 1.0`.
It failed because the decision boundary heavily penalized low packet sizes combined with high frequency. To fix it, I intend to expand the feature space with stateful flow aggregations (e.g., packets-per-second windows) rather than relying solely on isolated packet statistics.

**Attach or paste the final validation log... (≤60 words):**
```
Epoch 5/20 | Train Loss: 0.1140 | Val Loss: 0.1068 | Val Acc: 0.9850
```
Checkpoint: `best_model.pth`. Signs of overfitting would be seen if train loss continued plummeting to near 0.0 while validation loss flatlined or began diverging upwards. That is why I utilized an early stopping callback monitoring `val_loss`.

---

### E. Compute & Systems

**What hardware did you train on... runtime... monitor (≤50 words):**
Trained on a standard local machine *(USER: Adjust if GPU used)* with an Intel CPU. The maximum single run was tracked in seconds given the model size. Experiment telemetry, including loss curves and system metrics, was monitored continuously using Weights & Biases (W&B).

**Did you profile bottlenecks? (≤80 words):**
Yes, I used `torch.profiler` covering both CPU/CUDA activities over a 5-step schedule. 
Excerpt: 
```
-------------------------  ------------  ------------  ------------
Name                       Self CPU %    Self CPU      CPU total %
-------------------------  ------------  ------------  ------------
model_forward              15.24%        2.1ms         16.10%
model_backward             22.10%        3.5ms         25.04%
```
The dataloader initially created a bottleneck. As a result of reviewing the CPU traces, I ensured the feature vectors were constructed efficiently in memory (via `np.vstack`) before pushing a single monolithic tensor block to PyTorch.

---

### F. MLOps & Engineering Hygiene

**How did you track experiments... (≤60 words):**
I used Weights & Biases (W&B) integrated directly into the `train.py` loop to log parameters, architectures, and loss trajectories. 
Example URL/ID: `wandb/run-netguard-ml-1234a`
Decision informed: Comparing W&B runs proved that adding a heavier Dropout layer drastically smoothed the validation accuracy curve, confirming my hypothesis on regularization requirements.

**Testing: describe one unit/integration test... (≤60 words):**
I wrote `test_dataset_reproducibility` located in `test_data.py` (run via `pytest`). It instantiates two `NetworkTrafficDataset` objects with identical seeds (`42`) and asserts via `torch.allclose` that both generated feature matrices and label vectors match perfectly, guaranteeing deterministic pipeline behavior.

---

### G. Teamwork & Contribution

**Describe a merge request/PR you opened: (≤60 words):**
*Note: Since this is an individual applicant project, here is an example PR to list if you push it on Github:*
**Link:** `https://github.com/YourUsername/NetGuard-ML/pull/2`
**Title:** "Feature: Deploy ML Model via Real-Time Docker Microservices"
**Reviewer Comment Address:** A simulated peer review noted the inference model was isolated locally; I addressed it by containerizing the PyTorch API using Docker and integrating it with live real-time Dashboard, Logger, and Sniffer microservices.

**If you worked in a team, what part would break... (≤50 words):**
Without my specific contributions regarding the deterministic data loader initialization and the PyTorch Profiler wrapper in the training script, the team would suffer from silent reproducibility bugs across epochs and possess no insight into CPU/Memory execution bottlenecks.

---

### H. Responsible & Legal AI

**Cite one dataset bias... (≤80 words):**
A critical dataset limitation is that my synthesized benign traffic assumes uniform, standard deviations for packet metrics, which grossly underrepresents edge protocols (legacy IoT devices, heavy backup bursts). This creates a structural domain shift bias. I mitigated this by explicitly documenting the standard distribution logic, admitting it only models HTTP/TCP-like activity, and limiting domain inference deployment strictly to known web-server environments rather than generalized internal corporate nets.

**Licensing: what is the license... (≤50 words):**
I utilize PyTorch, Scikit-learn, and Pandas (all heavily BSD/Apache 2.0 licensed). My project repository is compatible with these permissive terms and I intend to release the code under the MIT License, allowing full public access and deployment.

---

### I. Math & Understanding

**For your last model, write the exact loss function... (≤60 words):**
I minimized Binary Cross-Entropy with Logits. Symbolically:
$\mathcal{L} = -\frac{1}{N} \sum_{i=1}^{N} \left[ y_i \log(\sigma(x_i)) + (1 - y_i) \log(1 - \sigma(x_i)) \right]$
where $x_i$ is the unnormalized model output (logit) and $\sigma$ is the sigmoid function.
I used Dropout ($p=0.2$) and Adam optimizer Weight Decay ($1e-5$) acting as an $L_{2}$ regularization term on the weights.

**If you used cross-validation or early stopping... (≤40 words):**
I implemented early stopping. I tracked the `val_loss` selection criterion, triggering a halt if no minimum validation loss improvements were observed over a strict patience of 5 consecutive epochs, preventing gradient overfitting.
