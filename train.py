import torch
import torch.nn as nn
import torch.optim as optim
from torch.profiler import profile, record_function, ProfilerActivity
import wandb
import random
import numpy as np
import os
import argparse

from dataset import get_dataloaders
from model import TrafficClassifierMLP

def set_all_seeds(seed=42):
    """Ensure deterministic behavior where possible."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    # One source of remaining nondeterminism: cuDNN convolution benchmarking or atomic operations on GPU
    # Although we can set deterministic behavior, it might slow things down
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

def train(args):
    # Set seeds
    set_all_seeds(args.seed)
    
    # Initialize W&B
    wandb.init(project="netguard-ml", config=vars(args))
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Training on device: {device}")
    
    # Data & Model
    train_loader, val_loader = get_dataloaders(num_samples=args.num_samples, batch_size=args.batch_size, seed=args.seed)
    model = TrafficClassifierMLP(input_dim=6, hidden_dim=args.hidden_dim, dropout_rate=args.dropout).to(device)
    
    # Loss & Optimizer
    # We minimize BCEWithLogitsLoss, symbolically: 
    # Loss = -1/N * sum(y_i * log(sigmoid(x_i)) + (1-y_i) * log(1-sigmoid(x_i)))
    criterion = nn.BCEWithLogitsLoss()
    optimizer = optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay) # weight_decay acts as L2 regularization
    
    # Initialize PyTorch Profiler
    prof = profile(
        activities=[ProfilerActivity.CPU] + ([ProfilerActivity.CUDA] if torch.cuda.is_available() else []),
        schedule=torch.profiler.schedule(wait=1, warmup=1, active=3, repeat=1),
        on_trace_ready=torch.profiler.tensorboard_trace_handler('./log/profiler'),
        record_shapes=True,
        profile_memory=True,
        with_stack=True
    )
    prof.start()

    best_val_loss = float('inf')
    early_stop_patience = 5
    patience_counter = 0
    
    for epoch in range(args.epochs):
        model.train()
        train_loss = 0.0
        
        for batch_idx, (features, labels) in enumerate(train_loader):
            features, labels = features.to(device), labels.to(device)
            
            optimizer.zero_grad()
            with record_function("model_forward"):
                outputs = model(features)
            with record_function("model_backward"):
                loss = criterion(outputs, labels)
                loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            prof.step()
            
        train_loss /= len(train_loader)
        
        # Validation
        model.eval()
        val_loss = 0.0
        correct = 0
        total = 0
        
        # To simulate error analysis failure modes
        misclassified_examples = []
        
        with torch.no_grad():
            for features, labels in val_loader:
                features, labels = features.to(device), labels.to(device)
                outputs = model(features)
                loss = criterion(outputs, labels)
                val_loss += loss.item()
                
                preds = (torch.sigmoid(outputs) > 0.5).float()
                correct += (preds == labels).sum().item()
                total += labels.size(0)
                
                # Finding specific failures for error analysis
                errors = (preds != labels).squeeze()
                if errors.any():
                    err_idx = torch.where(errors)[0]
                    for idx in err_idx:
                        misclassified_examples.append({
                            'features': features[idx].cpu().numpy().tolist(),
                            'true': labels[idx].item(),
                            'pred': preds[idx].item()
                        })
                
        val_loss /= len(val_loader)
        val_acc = correct / total
        
        wandb.log({
            "epoch": epoch,
            "train_loss": train_loss,
            "val_loss": val_loss,
            "val_accuracy": val_acc
        })
        
        print(f"Epoch {epoch+1}/{args.epochs} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}")
        
        # Save checkpoint if better
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_loss': val_loss,
            }, "best_model.pth")
        else:
            patience_counter += 1
            if patience_counter >= early_stop_patience:
                print(f"Early stopping at epoch {epoch+1}")
                break

    prof.stop()
    wandb.finish()
    
    if misclassified_examples:
        print(f"\nError Analysis Mode:")
        print(f"Found {len(misclassified_examples)} misclassified examples. First failure:")
        print(misclassified_examples[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--lr', type=float, default=1e-3, help='Learning rate')
    parser.add_argument('--batch_size', type=int, default=64, help='Batch size')
    parser.add_argument('--epochs', type=int, default=20, help='Max epochs')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    parser.add_argument('--hidden_dim', type=int, default=64, help='Hidden dimension size')
    parser.add_argument('--dropout', type=float, default=0.2, help='Dropout rate')
    parser.add_argument('--weight_decay', type=float, default=1e-5, help='L2 weight decay')
    parser.add_argument('--num_samples', type=int, default=10000, help='Dataset size')
    
    args = parser.parse_args()
    train(args)
