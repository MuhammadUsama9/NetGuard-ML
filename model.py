import torch
import torch.nn as nn

class TrafficClassifierMLP(nn.Module):
    """
    Multi-layer perceptron for binary classification of network traffic.
    We choose an MLP because the tabular nature of network flows (lengths, times)
    does not require spatial (CNN) or sequential (RNN/LSTM) inductive biases, 
    making MLP computationally cheap and interpretative.
    """
    def __init__(self, input_dim=6, hidden_dim=64, dropout_rate=0.2):
        super().__init__()
        
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_rate), # Regularization term
            
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            # Output is unnormalized logits, suitable for BCEWithLogitsLoss
            nn.Linear(hidden_dim // 2, 1) 
        )
        
    def forward(self, x):
        return self.net(x)
