import re
import aiohttp
import brotli
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

# Enhanced gateway detection patterns
GATEWAYS = {
    "Stripe": [
        r"<script[^>]*src=['\"]https?://js\.stripe\.com/v\d/['\"]",
        r"<script[^>]*src=['\"]https?://r\.stripe\.com/b['\"]",
        r"stripe\.com/v\d/tokens",
        r"stripe\.com/v\d/payment_intents",
        r"checkout\.stripe\.com",
        r"stripe\.com/v\d/elements",
        r"Stripe$$(['\"](pk_live|pk_test)_[0-9a-zA-Z]+['\"]$$",
        r"stripe\.createToken",
        r"stripe\.confirmCardPayment",
        r"stripe\.handleCardPayment",
        r"stripe\.createPaymentMethod",
        r"stripe\.elements$$$$",
        r"data-stripe=['\"][^'\"]+['\"]",
        r"id=['\"]card-element['\"]",
        r"stripeTokenHandler",
        r"stripe-button",
        r"stripe-payment",
        r"stripeBilling"
    ],
    "Braintree": [
        r"<script[^>]*src=['\"]https?://js\.braintreegateway\.com/[^'\"]+['\"]",
        r"<script[^>]*src=['\"]https?://api\.braintreegateway\.com/[^'\"]+['\"]",
        r"client_token_url",
        r"braintree_client_token",
        r"braintree/client_token",
        r"braintree\.setup",
        r"braintree\.client\.create",
        r"braintree\.paypal\.create",
        r"braintree\.hostedFields\.create",
        r"braintree\.dropin\.create",
        r"data-braintree-name",
        r"braintree-payment-form",
        r"bt-card-number",
        r"bt-expiration",
        r"bt-cvv",
        r"braintree\.env\.sandbox",
        r"braintree\.env\.production",
        r"braintree-hosted-fields-invalid",
        r"braintree-hosted-fields-valid"
    ],
    "PayPal": [
        r"paypal\.com/sdk/js",
        r"<script[^>]*src=['\"]https?://www\.paypalobjects\.com/[^'\"]+['\"]",
        r"paypal\.Buttons",
        r"paypal-button",
        r"paypal-payment",
        r"paypal\.com/v1/",
        r"paypal\.com/v2/checkout",
        r"paypal\.com/smart/buttons",
        r"data-paypal-button",
        r"paypal\.FUNDING\.",
        r"paypal-sdk",
        r"paypal-instance",
        r"paypal\.Orders\.create"
    ],
    "Square": [
        r"squareup\.com/payments",
        r"square\.com/js/sq-payment-form",
        r"SqPaymentForm",
        r"square-payment-form",
        r"SquarePaymentFlow",
        r"square\.com/v1/payments",
        r"square\.com/v2/payments",
        r"data-square",
        r"square-button"
    ],
    "Amazon Pay": [
        r"payments\.amazon\.",
        r"payments-amazon\.",
        r"amazonpayments\.",
        r"amazon\.Pay\.renderButton",
        r"amazon\.Pay\.initCheckout",
        r"OffAmazonPayments",
        r"amazon-pay-button",
        r"amazonpay-button"
    ],
    "Klarna": [
        r"klarna\.com",
        r"klarna-payments",
        r"klarna-checkout",
        r"klarna\.load",
        r"KlarnaPayments",
        r"klarna_payments",
        r"klarna-payment-method",
        r"_klarnaCheckout"
    ],
    "Adyen": [
        r"adyen\.com",
        r"checkoutshopper-live\.adyen\.com",
        r"checkoutshopper-test\.adyen\.com",
        r"adyen\.checkout",
        r"AdyenCheckout",
        r"adyen-checkout",
        r"adyen-encrypted-data",
        r"data-adyen"
    ],
    "Authorize.net": [
        r"accept\.authorize\.net",
        r"acceptjs\.authorize\.net",
        r"AcceptUI",
        r"accept\.js",
        r"authorizenet",
        r"authorize-net",
        r"AuthorizeNetSeal",
        r"AuthorizeNetPopup"
    ],
    "Worldpay": [
        r"worldpay\.com",
        r"worldpay\.js",
        r"worldpay-js",
        r"WorldpayHOP",
        r"worldpay\.setup",
        r"data-worldpay",
        r"worldpay-payment"
    ],
    "Cybersource": [
        r"cybersource\.com",
        r"cybersource\.min\.js",
        r"cybersource/checkout",
        r"cybs",
        r"cybersource-flex",
        r"cybersource-token",
        r"data-cybersource"
    ],
    "2Checkout": [
        r"2checkout\.com",
        r"2co\.com",
        r"2checkout\.js",
        r"2co_signature",
        r"twocheckout",
        r"2checkout-form",
        r"2checkout-token"
    ],
    "Eway": [
        r"eway\.com\.au",
        r"eWAY",
        r"eway\.rapidapi"
    ],
    "NMI": [
        r"secure\.networkmerchants\.com",
        r"CollectJS",
        r"collect\.js"
    ],
    "WooCommerce": [
        r"woocommerce",
        r"WC_AJAX",
        r"wc-payment"
    ]
}

# Enhanced captcha detection patterns
CAPTCHA_TYPES = {
    "reCAPTCHA v2": [
        r"www\.google\.com/recaptcha/api\.js",
        r"grecaptcha\.render",
        r"g-recaptcha",
        r"recaptcha-token",
        r"data-sitekey=\"[^\"]*\"",
        r"class=\"g-recaptcha\"",
        r"grecaptcha\.execute"
    ],
    "reCAPTCHA v3": [
        r"grecaptcha\.execute\('[^']+', *{action:",
        r"google\.com/recaptcha/api\.js\?render=",
        r"grecaptcha\.ready",
        r"data-recaptcha-action"
    ],
    "hCaptcha": [
        r"hcaptcha\.com/1/api\.js",
        r"data-hcaptcha",
        r"h-captcha",
        r"hcaptcha-response",
        r"hcaptcha\.render",
        r"hcaptcha-widget"
    ],
    "Arkose Labs": [
        r"arkoselabs\.com",
        r"funcaptcha",
        r"arkoselabs-client",
        r"data-callback=\"arkoseCallback\"",
        r"arkose-enforcement"
    ],
    "Custom Captcha": [
        r"captcha\.php",
        r"custom-captcha",
        r"captcha-form",
        r"captcha-image",
        r"captcha-input",
        r"captcha\.generate",
        r"captcha\.verify"
    ],
    "BotDetect": [
        r"botdetect/",
        r"BotDetect\.init",
        r"BDC_",
        r"botdetect-captcha"
    ],
    "KeyCaptcha": [
        r"keycaptcha\.com",
        r"s_s_c_user_id",
        r"KeyCAPTCHA_"
    ],
    "GeeTest": [
        r"geetest\.com",
        r"gt_captcha",
        r"initGeetest",
        r"geetest_challenge"
    ]
}

async def check_gateway(url):
    """
    Enhanced gateway checking with advanced detection methods
    """
    try:
        async with aiohttp.ClientSession() as session:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }

            async with session.get(url, ssl=False, timeout=15, headers=headers) as response:
                content = await response.read()
                try:
                    if response.headers.get('Content-Encoding') == 'br':
                        html = brotli.decompress(content).decode('utf-8')
                    else:
                        html = content.decode('utf-8')
                except brotli.error:
                    logger.error(f"Failed to decompress Brotli-encoded content for URL: {url}")
                    return {"error": "Failed to decompress Brotli-encoded content"}
                except UnicodeDecodeError:
                    logger.error(f"Failed to decode content for URL: {url}")
                    return {"error": "Failed to decode content"}

                status_code = response.status

                # Gateway detection
                gateways_found = []
                for gateway, patterns in GATEWAYS.items():
                    if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                        gateways_found.append(gateway)

                # Captcha detection
                captcha_detected = False
                captcha_types = []
                for captcha_type, patterns in CAPTCHA_TYPES.items():
                    if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                        captcha_detected = True
                        captcha_types.append(captcha_type)

                # Cloudflare detection
                cloudflare_detected = bool(re.search(r"cloudflare", html, re.IGNORECASE))

                # Payment security types (simplified check)
                payment_security = []
                if re.search(r"3D(-|\s)?Secure", html, re.IGNORECASE):
                    payment_security.append("3D Secure")
                if re.search(r"CVV|CVC|Security Code", html, re.IGNORECASE):
                    payment_security.append("CVV Required")

                return {
                    "status_code": status_code,
                    "gateways": gateways_found,
                    "captcha": {
                        "detected": captcha_detected,
                        "types": captcha_types
                    },
                    "cloudflare": cloudflare_detected,
                    "payment_security": payment_security,
                }

    except aiohttp.ClientError as e:
        logger.error(f"Connection error for URL {url}: {str(e)}")
        return {"error": f"🔌 Connection error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error for URL {url}: {str(e)}")
        return {"error": f"❌ Unexpected error: {str(e)}"}

