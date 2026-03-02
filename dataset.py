import torch
from torch.utils.data import Dataset, DataLoader
import numpy as np

class NetworkTrafficDataset(Dataset):
    """
    Synthetic dataset for network traffic classification (benign vs malicious).
    Features representing: 
      0: packet_length
      1: inter_arrival_time
      2: protocol_tcp
      3: protocol_udp
      4: source_port
      5: destination_port
    """
    def __init__(self, num_samples=10000, seed=42):
        self.num_samples = num_samples
        
        # Set seeds for reproducibility
        np.random.seed(seed)
        torch.manual_seed(seed)
        
        # Generate synthetic features
        # Benign traffic (Normal web browsing, wide range of packet lengths, random high source ports to 80/443)
        benign_samples = num_samples // 2
        
        # We need a much wider variance for benign to not overfit "normal" to just port 80/443 and exactly 500 bytes.
        # loc:   [packet_length, inter_arrival_time, protocol_tcp, protocol_udp, source_port, dest_port]
        # We will use high standard deviations for lengths and source ports.
        benign_features = np.random.normal(
            loc=[700, 0.5, 1, 0, 40000, 443], 
            scale=[600, 0.5, 0.5, 0.5, 20000, 200], # Big variance
            size=(benign_samples, 6)
        )
        benign_labels = np.zeros(benign_samples)
        
        # Malicious traffic (DDoS-like characteristics: very small packets, extremely high frequency/low inter-arrival)
        mal_samples = num_samples - benign_samples
        mal_features = np.random.normal(
            loc=[64, 0.0001, 0, 1, 50000, 80], 
            scale=[10, 0.00005, 0.1, 0.1, 5000, 0], 
            size=(mal_samples, 6)
        )
        mal_labels = np.ones(mal_samples)
        
        self.features = np.vstack([benign_features, mal_features])
        self.labels = np.concatenate([benign_labels, mal_labels])
        
        # Simulated data cleaning: clip non-physical values
        self.features[:, 0] = np.clip(self.features[:, 0], 20, 1500) # packet length
        self.features[:, 1] = np.clip(self.features[:, 1], 0, None)  # inter_arrival_time >= 0
        
        # Ensure exact float32 types for PyTorch
        self.features = torch.tensor(self.features, dtype=torch.float32)
        self.labels = torch.tensor(self.labels, dtype=torch.float32).unsqueeze(1)
        
    def __len__(self):
        return self.num_samples
    
    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]

def get_dataloaders(num_samples=10000, batch_size=64, seed=42, val_split=0.2):
    # Deterministic behavior for reproducibility
    generator = torch.Generator()
    generator.manual_seed(seed)
    
    dataset = NetworkTrafficDataset(num_samples=num_samples, seed=seed)
    val_size = int(num_samples * val_split)
    train_size = num_samples - val_size
    
    train_dataset, val_dataset = torch.utils.data.random_split(
        dataset, [train_size, val_size], generator=generator
    )
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, worker_init_fn=lambda worker_id: np.random.seed(seed + worker_id))
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    
    return train_loader, val_loader

if __name__ == "__main__":
    train_dl, val_dl = get_dataloaders()
    print(f"Train batches: {len(train_dl)}, Val batches: {len(val_dl)}")
    for x, y in train_dl:
        print(f"Batch X shape: {x.shape}, Batch Y shape: {y.shape}")
        break
