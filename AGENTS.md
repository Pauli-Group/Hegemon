# Always Be Shipping

The product must be made real, not a mock up.

# ExecPlans

When writing complex features or significant refactors, use an ExecPlan (as described in .agent/PLANS.md) from design to implementation.

# First-Run Setup

Every fresh clone must begin with `make quickstart`. This single command bootstraps the toolchains, runs the guard-rail checks, and launches the FastAPI streaming service plus the Vite dashboard UI so contributors land inside the graphical experience immediately (press Ctrl+C when you want to stop it).

# Design and Methods Docs

Always consult DESIGN.md and METHODS.md before making code changes to ensure the implementation aligns with the documented plans, and update those documents whenever the architecture or methods evolve.

# README Whitepaper

Maintain the opening section of `README.md` as the canonical whitepaper for the project. The whitepaper must appear before the "Monorepo layout" and "Getting started" sections and must preserve the document title and subtitle.

# Branding Guidelines

Whenever you design or adjust any visual element, interface component, or documentation mock-up, consult `BRAND.md` to ensure colors, typography, layout, and motion adhere to the shared system. Document any intentional deviations in the relevant pull request.
