import pandas as pd
import matplotlib.pyplot as plt

# Read data from CSV
df = pd.read_csv("tables/data.csv", header=None)

# Define the parameters and their indexes for subplots (2 rows and 3 columns of plots)
parameters = ["RSA_key_enc", "RSA_key_dec", "enc", "dec", "writer", "reader"]
n_rows = 2
n_cols = 3

# Create a figure with subplots
fig, axs = plt.subplots(n_rows, n_cols, figsize=(15, 10))

# Flatten the array of axes for easy iteration
axs = axs.flatten()

for i, param in enumerate(parameters):
    # Filter data for each parameter
    param_data = df[df.iloc[:, 2] == param]  # Selecting the 3rd column
    # Combine method and mode for x-axis labels
    x_labels = param_data.iloc[:, 0].astype(str) + " (" + param_data.iloc[:, 1].astype(str) + ")"
    # Plot on the i-th subplot
    axs[i].bar(x_labels, param_data.iloc[:, 3])
    axs[i].set_title(f"{param} Duration Comparison")
    axs[i].set_xlabel("Encryption Method (Mode)")
    axs[i].set_ylabel("Duration (microseconds)")
    axs[i].tick_params(labelrotation=90)  # Rotate the x-axis labels for readability

# Adjust the layout so the subplots fit into the figure nicely
plt.tight_layout()
# Save the figure with all subplots
plt.savefig('all_parameters_duration_comparison.png')
plt.close()  # Close the figure after saving to file