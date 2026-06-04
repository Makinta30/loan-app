# Farmers Alliance & Business Boost Loan (Demo)

This is a minimal demo loan application with:
- Signup, login and forgotten password templates (EJS)
- Dashboard prompting BVN verification
- Loan categories and deposit calculation by tier
- Paystack inline payment for deposit
- Simple SQLite storage for users, loans and payments

Setup

1. Copy `.env.example` to `.env` and fill `PAYSTACK_PUBLIC_KEY` and `PAYSTACK_SECRET_KEY`.
2. Install dependencies:

```bash
npm install
```

3. Run the app:

```bash
npm start
```

Open http://localhost:3000

Notes
- BVN verification is simulated (checks 11 digits).
- Payment verification calls Paystack verify endpoint — use test keys for sandbox.
- This is a demo starter; secure and production-hardening steps are required before real usage.
