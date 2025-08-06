# Edenred España Client

A comprehensive Python client for accessing Edenred España services. This tool allows you to retrieve card balances, transaction history, and calculate weekly spending limits for your Edenred cards (Ticket Restaurant, Edenred Guardería, etc.).

## Features

- 🔐 **Secure Authentication**: Full OAuth 2.0 and OTP support
- 💳 **Card Management**: View balances and status for all your Edenred cards
- 📊 **Transaction History**: Complete transaction retrieval with pagination
- 📅 **Weekly Spending Tracker**: Calculate weekly spending limits (perfect for restaurant vouchers)
- 🎯 **Flexible Filtering**: Filter by card type, date ranges, and more
- 📁 **Multiple Export Formats**: JSON, CSV, and formatted text output
- 🚀 **Mobile API Support**: Uses captured mobile tokens for enhanced access

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd edenred
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Commands

```bash
# View all cards and balances
python edenred_client.py --user your_username --password your_password

# Check only card balances
python edenred_client.py --user your_username --password your_password --only-balance

# Calculate weekly spending with limit (e.g., 55€ restaurant vouchers)
python edenred_client.py --user your_username --password your_password --weekly-limit 55.0

# Export to JSON format
python edenred_client.py --user your_username --password your_password --format json --output data.json

# Filter specific card and date range
python edenred_client.py --user your_username --password your_password --card-name "Ticket Restaurant" --begin-date 2025-01-01
```

### Advanced Options

| Option | Description | Example |
|--------|-------------|---------|
| `--user` | Edenred username (required) | `--user myuser` |
| `--password` | Edenred password (required) | `--password mypass` |
| `--weekly-limit` | Weekly spending limit in euros | `--weekly-limit 55.0` |
| `--begin-date` | Start date for transactions (YYYY-MM-DD) | `--begin-date 2025-01-01` |
| `--card-name` | Filter by specific card name | `--card-name "Ticket Restaurant"` |
| `--only-balance` | Show only card balances | `--only-balance` |
| `--only-transactions` | Show only transactions | `--only-transactions` |
| `--format` | Output format: text, json, csv | `--format json` |
| `--output` | Output file path | `--output report.json` |
| `--debug` | Enable detailed logging | `--debug` |

## Weekly Spending Tracker

The weekly spending tracker is perfect for managing restaurant voucher limits:

```bash
python edenred_client.py --user myuser --password mypass --weekly-limit 55.0
```

This will show:
- Current week's spending (Monday to Sunday)
- Remaining budget for the week
- Percentage of limit used
- List of this week's transactions

## Output Examples

### Text Format (Default)
```
============================================================
📊 RESUMEN DE CUENTA EDENRED
============================================================
👤 Usuario: John Doe
💳 Total tarjetas: 1
💰 Saldo total: 156.40€
============================================================

📅 RESUMEN SEMANAL - TICKET RESTAURANT
============================================================
📆 Semana actual: 2025-08-04 al 2025-08-10
💳 Tarjeta: Ticket Restaurant
🎯 Límite semanal: 55.00€
💸 Gastado esta semana: 12.50€
✅ Disponible restante: 42.50€
📊 Porcentaje usado: 22.7%
```

### JSON Format
```json
{
  "user_name": "John Doe",
  "cards": [
    {
      "cardName": "Ticket Restaurant",
      "balance": 156.4,
      "cardGuid": "19e0459f-e0da-4d87-88b1-65e4c48c36f2"
    }
  ],
  "weekly_summary": {
    "weekly_limit": 55.0,
    "weekly_spent": 12.5,
    "weekly_remaining": 42.5,
    "week_start": "2025-08-04",
    "week_end": "2025-08-10"
  }
}
```

## Architecture

The client uses a hybrid approach:
1. **Mobile API Priority**: Uses captured mobile tokens for enhanced access
2. **Web API Fallback**: Falls back to traditional web authentication if mobile fails
3. **Smart Card Detection**: Automatically filters active/inactive cards
4. **Robust Error Handling**: Graceful handling of authentication and API issues

## Security Features

- 🔐 **OTP Support**: Automatic handling of two-factor authentication
- 🛡️ **Secure Token Management**: Proper JWT and Bearer token handling
- 🚫 **No Credential Storage**: Credentials are only used during authentication
- 🔒 **Session Management**: Proper session cleanup and security headers

## Requirements

- Python 3.8+
- requests >= 2.31.0
- beautifulsoup4 >= 4.12.0

## Error Handling

The client includes comprehensive error handling for:
- Network connectivity issues
- Authentication failures (including OTP)
- API rate limiting
- Invalid card/transaction data
- SSL certificate issues

## Development

### Running with Debug Mode
```bash
python edenred_client.py --user myuser --password mypass --debug
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Common Use Cases

### Restaurant Voucher Management
Perfect for employees with weekly restaurant voucher limits:
```bash
# Check weekly spending every Monday
python edenred_client.py --user myuser --password mypass --weekly-limit 55.0
```

### Monthly Reporting
Generate monthly reports for expense tracking:
```bash
# Export last month's data
python edenred_client.py --user myuser --password mypass --begin-date 2025-07-01 --format csv --output july_2025.csv
```

### Balance Monitoring
Quick balance checks for multiple cards:
```bash
# Fast balance check
python edenred_client.py --user myuser --password mypass --only-balance
```

## Troubleshooting

### Authentication Issues
- Ensure your credentials are correct
- Check if OTP is required and enter the 6-digit code when prompted
- Try running with `--debug` for detailed logs

### No Transactions Found
- Verify the date range with `--begin-date`
- Check if the card name filter is correct
- Ensure the card is active and has transactions

### SSL Certificate Errors
- This usually indicates a corporate proxy
- Contact your IT department for proper certificate configuration

## License

This project is for educational and personal use only. Please respect Edenred's terms of service.

## Disclaimer

This tool is not officially affiliated with Edenred. Use responsibly and in accordance with Edenred's terms of service.
