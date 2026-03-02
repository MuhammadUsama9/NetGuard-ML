import pytest
import torch
from dataset import NetworkTrafficDataset, get_dataloaders

def test_dataset_reproducibility():
    """Unit test to verify random seed controls nondeterminism in data generation."""
    ds1 = NetworkTrafficDataset(num_samples=100, seed=42)
    ds2 = NetworkTrafficDataset(num_samples=100, seed=42)
    
    assert torch.allclose(ds1.features, ds2.features), "Features should be identical for same seed"
    assert torch.allclose(ds1.labels, ds2.labels), "Labels should be identical for same seed"

def test_dataloader_shapes():
    """Unit test to verify dataloader batch dimensions are correct."""
    train_dl, val_dl = get_dataloaders(num_samples=1000, batch_size=16)
    
    x, y = next(iter(train_dl))
    assert x.shape == (16, 6), "Feature batch shape should be (batch_size, num_features)"
    assert y.shape == (16, 1), "Label batch shape should be (batch_size, 1)"
