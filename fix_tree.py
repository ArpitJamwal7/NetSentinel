import os
import subprocess

# Get the original tree from 2965840
subprocess.run(["git", "ls-tree", "2965840"], stdout=open("tree.txt", "wb"))

with open("tree.txt", "rb") as f:
    lines = f.readlines()

with open("filtered_tree.txt", "wb") as f:
    for line in lines:
        if b'Nmap_AutoRecon.py\\\\' not in line and b'"Nmap_AutoRecon.py\\\\"' not in line:
            f.write(line)

# Create the new tree
with open("filtered_tree.txt", "rb") as f:
    result = subprocess.run(["git", "mktree"], stdin=f, capture_output=True)
    tree_hash = result.stdout.decode('utf-8').strip()

# Create the commit
result = subprocess.run(["git", "commit-tree", tree_hash, "-p", "2965840", "-m", "Remove invalid path Nmap_AutoRecon.py"], capture_output=True)
commit_hash = result.stdout.decode('utf-8').strip()

# Push force to main
os.system(f"git push origin {commit_hash}:main --force")
