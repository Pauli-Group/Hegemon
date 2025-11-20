#!/bin/bash
set -e

echo "Building Dashboard UI..."
cd dashboard-ui
npm install
npm run build
cd ..

echo "Copying assets to node/src/dashboard/assets..."
mkdir -p node/src/dashboard/assets
rm -rf node/src/dashboard/assets/*
cp -r dashboard-ui/dist/* node/src/dashboard/assets/

echo "Dashboard built and embedded."
