# BOM Stock Backend

## Upload to GitHub
Upload these files to your `bom-stock-backend` repository.

## Render settings
Build Command:
```bash
npm install
```

Start Command:
```bash
node server.js
```

## Environment Variables
```env
PORT=4000
DB_HOST=your_mysql_host
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
DB_NAME=bom_stock_app
JWT_SECRET=change-this-secret-key
```

## Test
Open:
```txt
https://your-render-url.onrender.com/api/health
```


## Railway public MySQL note
Render needs `DB_PORT`, for example:
DB_PORT=35611

Test DB:
https://your-render-url.onrender.com/api/db-test
