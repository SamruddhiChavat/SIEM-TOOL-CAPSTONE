#!/bin/bash
cd "/Users/jesalshah/Documents/Secure watch/realsiem"

# 1. Create top level directories
mkdir -p client/dashboard client/sandbox
mkdir -p server/api server/relay

# 2. Move client apps
mv sentinel-watch/* sentinel-watch/.* client/dashboard/ 2>/dev/null || true
rmdir sentinel-watch

# Move sandbox (except server)
mv "SIEM ENV/src" "SIEM ENV/public" "SIEM ENV/index.html" "SIEM ENV/package.json" "SIEM ENV/vite.config.ts" "SIEM ENV/eslint.config.js" "SIEM ENV/tsconfig."* "SIEM ENV/.gitignore" client/sandbox/ 2>/dev/null || true

# 3. Move python backend
mv backend/* backend/.* server/api/ 2>/dev/null || true
rmdir backend

# Rename routers to routes in Python backend
if [ -d "server/api/routers" ]; then
    mv server/api/routers server/api/routes
    # Update imports in Python files
    find server/api -type f -name "*.py" -exec sed -i '' 's/routers\./routes\./g' {} +
    find server/api -type f -name "*.py" -exec sed -i '' 's/from routers/from routes/g' {} +
    find server/api -type f -name "*.py" -exec sed -i '' 's/import routers/import routes/g' {} +
fi

# 4. Move Node relay server
mv "SIEM ENV/server/"* "SIEM ENV/server/".* server/relay/ 2>/dev/null || true
rm -rf "SIEM ENV"

# 5. Restructure Node Server (MVC pattern)
cd server/relay
mkdir -p controllers routes services models config middleware utils

# We'll populate these files in the next step using Node scripts or cat, for now just empty them out
# We will create the MVC structure and delete index.js

