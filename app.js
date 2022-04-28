const crypto = require('crypto');
const nonce = require('nonce')();
const request = require('request-promise');
const querystring = require('querystring');
const express = require('express');
const {google} = require('googleapis');
require("dotenv").config();

const app = express();
app.use(express.json());

app.get('/login', (req, res) => {
    const shopName = process.env.SHOP_NAME;

    const shopState = nonce();

    const redirectURL = process.env.TUNNEL_URL + '/login/callback';

    const shopifyURL = 'https://' + shopName +
        '/admin/oauth/authorize?client_id=' + process.env.SHOPIFY_API_KEY +
        '&scope=' + process.env.SCOPES +
        '&state=' + shopState +
        '&redirect_uri=' + redirectURL;

    res.cookie('state', shopState);
    res.redirect(shopifyURL);
});

app.get('/login/callback', (req, res) => {
    shop = req.query.shop;
    hmac = req.query.hmac;
    code = req.query.code;
    state = req.query.state;

    if (shop && hmac && code) {
        const queryMap = Object.assign({}, req.query);
        delete queryMap['signature'];
        delete queryMap['hmac'];

        const message = querystring.stringify(queryMap);
        const providedHmac = Buffer.from(hmac, 'utf-8');
        const generatedHash = Buffer.from(crypto.createHmac('sha256', process.env.SHOPIFY_API_SECRET).update(message).digest('hex'), 'utf-8');

        let hashEquals = false;

        try {
            hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac);
        } catch (e) {
            hashEquals = false;
        }

        if (!hashEquals) {
            return res.status(400).send('HMAC validation failed');
        }

        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
            client_id: process.env.SHOPIFY_API_KEY,
            client_secret: process.env.SHOPIFY_API_SECRET,
            code,
        };

        request.post(accessTokenRequestUrl, {json: accessTokenPayload})
            .then((accessTokenResponse) => {
                const accessToken = accessTokenResponse.access_token;
                const draftOrdersUrl = 'https://' + shop + '/admin/api/2022-04/draft_orders.json';
                const requestHeaders = {'X-Shopify-Access-Token': accessToken};

                request.get(draftOrdersUrl, {headers: requestHeaders})
                    .then((draftOrdersResponse) => {
                        const responseObject = JSON.parse(draftOrdersResponse);

                        const draftOrders = responseObject.draft_orders;
                        const sheetId = process.env.GOOGLE_SHEET_ID;

                        (async() => {
                            const result = await addData(draftOrders, sheetId);
                            res.send(result);
                         })();
                    })
                    .catch((error) => {
                        res.status(error.statusCode).send(error.error.error_description);
                    });
            })
            .catch((error) => {
                res.status(error.statusCode).send(error.error.error_description);
            });

    } else {
        res.status(400).send('Required parameters missing');
    }
});

const addData = async (draftOrders, spreadsheetId) => {
    try {
        const {sheets} = await googleAuth();

        var values = [];

        for(let i = 0; i < draftOrders.length; i++) {
            values.push([draftOrders[i].id, draftOrders[i].status]);
        }

        const writeReq = await sheets.spreadsheets.values.append({
            spreadsheetId: spreadsheetId,
            range: 'Sheet1',
            valueInputOption: 'USER_ENTERED',
            resource: {
                values: values
            }
        })

        if(writeReq.status === 200) {
            return 'Data added to Google Sheet';
        } else {
            return 'Error ' + writeReq.status;
        }
    } catch(e) {
        return 'Error!';
    }
}

const googleAuth = async () => {
    const auth = new google.auth.GoogleAuth({
        keyFile: "credentials.json", 
        scopes: "https://www.googleapis.com/auth/spreadsheets", 
    });

    const client = await auth.getClient();

    const sheets = google.sheets({
        version: 'v4',
        auth: client
    });

    return {sheets};
}

app.listen(3434, () => console.log('Application listening on port 3434!'));