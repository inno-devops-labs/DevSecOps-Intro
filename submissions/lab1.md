# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Ubuntu 26.04
- Docker version: Docker version 29.5.3, build d1c06ef

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes
- Container restart policy: no

### Health Check
- HTTP code on `/`: HTTP 200
- API check (first 200 chars of `/api/Products`):
```
  {
  "status": "success",
  "data": [
    {
      "id": 1,
      "name": "Apple Juice (1000ml)",
      "description": "The all-time classic.",
      "price": 1.99,
      "deluxePrice": 0.99,
      "image": "apple_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 2,
      "name": "Orange Juice (1000ml)",
      "description": "Made from oranges hand-picked by Uncle Dittmeyer.",
      "price": 2.99,
      "deluxePrice": 2.49,
      "image": "orange_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 3,
      "name": "Eggfruit Juice (500ml)",
      "description": "Now with even more exotic flavour.",
      "price": 8.99,
      "deluxePrice": 8.99,
      "image": "eggfruit_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 4,
      "name": "Raspberry Juice (1000ml)",
      "description": "Made from blended Raspberry Pi, water and sugar.",
      "price": 4.99,
      "deluxePrice": 4.99,
      "image": "raspberry_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 5,
      "name": "Lemon Juice (500ml)",
      "description": "Sour but full of vitamins.",
      "price": 2.99,
      "deluxePrice": 1.99,
      "image": "lemon_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 6,
      "name": "Banana Juice (1000ml)",
      "description": "Monkeys love it the most.",
      "price": 1.99,
      "deluxePrice": 1.99,
      "image": "banana_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 7,
      "name": "OWASP Juice Shop T-Shirt",
      "description": "Real fans wear it 24/7!",
      "price": 22.49,
      "deluxePrice": 22.49,
      "image": "fan_shirt.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 8,
      "name": "OWASP Juice Shop CTF Girlie-Shirt",
      "description": "For serious Capture-the-Flag heroines only!",
      "price": 22.49,
      "deluxePrice": 22.49,
      "image": "fan_girlie.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 9,
      "name": "OWASP SSL Advanced Forensic Tool (O-Saft)",
      "description": "O-Saft is an easy to use tool to show information about SSL certificate and tests the SSL connection according given list of ciphers and various SSL configurations. <a href=\"https://www.owasp.org/index.php/O-Saft\" target=\"_blank\">More...</a>",
      "price": 0.01,
      "deluxePrice": 0.01,
      "image": "orange_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.933Z",
      "updatedAt": "2026-06-17T04:56:59.933Z",
      "deletedAt": null
    },
    {
      "id": 13,
      "name": "OWASP Juice Shop Iron-Ons (16pcs)",
      "description": "Upgrade your clothes with washer safe <a href=\"https://www.stickeryou.com/products/owasp-juice-shop/794\" target=\"_blank\">iron-ons</a> of the OWASP Juice Shop or CTF Extension logo!",
      "price": 14.99,
      "deluxePrice": 14.99,
      "image": "iron-on.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 14,
      "name": "OWASP Juice Shop Magnets (16pcs)",
      "description": "Your fridge will be even cooler with these OWASP Juice Shop or CTF Extension logo <a href=\"https://www.stickeryou.com/products/owasp-juice-shop/794\" target=\"_blank\">magnets</a>!",
      "price": 15.99,
      "deluxePrice": 15.99,
      "image": "magnets.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 15,
      "name": "OWASP Juice Shop Sticker Page",
      "description": "Massive decoration opportunities with these OWASP Juice Shop or CTF Extension <a href=\"https://www.stickeryou.com/products/owasp-juice-shop/794\" target=\"_blank\">sticker pages</a>! Each page has 16 stickers on it.",
      "price": 9.99,
      "deluxePrice": 9.99,
      "image": "sticker_page.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 16,
      "name": "OWASP Juice Shop Sticker Single",
      "description": "Super high-quality vinyl <a href=\"https://www.stickeryou.com/products/owasp-juice-shop/794\" target=\"_blank\">sticker single</a> with the OWASP Juice Shop or CTF Extension logo! The ultimate laptop decal!",
      "price": 4.99,
      "deluxePrice": 4.99,
      "image": "sticker_single.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 17,
      "name": "OWASP Juice Shop Temporary Tattoos (16pcs)",
      "description": "Get one of these <a href=\"https://www.stickeryou.com/products/owasp-juice-shop/794\" target=\"_blank\">temporary tattoos</a> to proudly wear the OWASP Juice Shop or CTF Extension logo on your skin! If you tweet a photo of yourself with the tattoo, you get a couple of our stickers for free! Please mention <a href=\"https://twitter.com/owasp_juiceshop\" target=\"_blank\"><code>@owasp_juiceshop</code></a> in your tweet!",
      "price": 14.99,
      "deluxePrice": 14.99,
      "image": "tattoo.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 18,
      "name": "OWASP Juice Shop Mug",
      "description": "Black mug with regular logo on one side and CTF logo on the other! Your colleagues will envy you!",
      "price": 21.99,
      "deluxePrice": 21.99,
      "image": "fan_mug.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 19,
      "name": "OWASP Juice Shop Hoodie",
      "description": "Mr. Robot-style apparel. But in black. And with logo.",
      "price": 49.99,
      "deluxePrice": 49.99,
      "image": "fan_hoodie.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 20,
      "name": "OWASP Juice Shop-CTF Velcro Patch",
      "description": "4x3.5\" embroidered patch with velcro backside. The ultimate decal for every tactical bag or backpack!",
      "price": 2.92,
      "deluxePrice": 2.92,
      "image": "velcro-patch.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 21,
      "name": "Woodruff Syrup \"Forest Master X-Treme\"",
      "description": "Harvested and manufactured in the Black Forest, Germany. Can cause hyperactive behavior in children. Can cause permanent green tongue when consumed undiluted.",
      "price": 6.99,
      "deluxePrice": 6.99,
      "image": "woodruff_syrup.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 22,
      "name": "Green Smoothie",
      "description": "Looks poisonous but is actually very good for your health! Made from green cabbage, spinach, kiwi and grass.",
      "price": 1.99,
      "deluxePrice": 1.99,
      "image": "green_smoothie.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 23,
      "name": "Quince Juice (1000ml)",
      "description": "Juice of the <em>Cydonia oblonga</em> fruit. Not exactly sweet but rich in Vitamin C.",
      "price": 4.99,
      "deluxePrice": 4.99,
      "image": "quince.jpg",
      "createdAt": "2026-06-17T04:56:59.934Z",
      "updatedAt": "2026-06-17T04:56:59.934Z",
      "deletedAt": null
    },
    {
      "id": 24,
      "name": "Apple Pomace",
      "description": "Finest pressings of apples. Allergy disclaimer: Might contain traces of worms. Can be <a href=\"/#recycle\">sent back to us</a> for recycling.",
      "price": 0.89,
      "deluxePrice": 0.89,
      "image": "apple_pressings.jpg",
      "createdAt": "2026-06-17T04:56:59.935Z",
      "updatedAt": "2026-06-17T04:56:59.935Z",
      "deletedAt": null
    },
    {
      "id": 25,
      "name": "Fruit Press",
      "description": "Fruits go in. Juice comes out. Pomace you can send back to us for recycling purposes.",
      "price": 89.99,
      "deluxePrice": 89.99,
      "image": "fruit_press.jpg",
      "createdAt": "2026-06-17T04:56:59.935Z",
      "updatedAt": "2026-06-17T04:56:59.935Z",
      "deletedAt": null
    },
    {
      "id": 26,
      "name": "OWASP Juice Shop Logo (3D-printed)",
      "description": "This rare item was designed and handcrafted in Sweden. This is why it is so incredibly expensive despite its complete lack of purpose.",
      "price": 99.99,
      "deluxePrice": 99.99,
      "image": "3d_keychain.jpg",
      "createdAt": "2026-06-17T04:56:59.935Z",
      "updatedAt": "2026-06-17T04:56:59.935Z",
      "deletedAt": null
    },
    {
      "id": 29,
      "name": "Strawberry Juice (500ml)",
      "description": "Sweet & tasty!",
      "price": 3.99,
      "deluxePrice": 3.99,
      "image": "strawberry_juice.jpeg",
      "createdAt": "2026-06-17T04:56:59.935Z",
      "updatedAt": "2026-06-17T04:56:59.935Z",
      "deletedAt": null
    },
    {
      "id": 30,
      "name": "Carrot Juice (1000ml)",
      "description": "As the old German saying goes: \"Carrots are good for the eyes. Or has anyone ever seen a rabbit with glasses?\"",
      "price": 2.99,
      "deluxePrice": 2.99,
      "image": "carrot_juice.jpeg",
      "createdAt": "2026-06-17T04:56:59.935Z",
      "updatedAt": "2026-06-17T04:56:59.935Z",
      "deletedAt": null
    },
    {
      "id": 32,
      "name": "Pwning OWASP Juice Shop",
      "description": "<em>The official Companion Guide</em> by Björn Kimminich available <a href=\"https://leanpub.com/juice-shop\">for free on LeanPub</a> and also <a href=\"https://pwning.owasp-juice.shop\">readable online</a>!",
      "price": 5.99,
      "deluxePrice": 5.99,
      "image": "cover_small.jpg",
      "createdAt": "2026-06-17T04:56:59.935Z",
      "updatedAt": "2026-06-17T04:56:59.935Z",
      "deletedAt": null
    },
    {
      "id": 33,
      "name": "Melon Bike (Comeback-Product 2018 Edition)",
      "description": "The wheels of this bicycle are made from real water melons. You might not want to ride it up/down the curb too hard.",
      "price": 2999,
      "deluxePrice": 2999,
      "image": "melon_bike.jpeg",
      "createdAt": "2026-06-17T04:56:59.935Z",
      "updatedAt": "2026-06-17T04:56:59.935Z",
      "deletedAt": null
    },
    {
      "id": 34,
      "name": "OWASP Juice Shop Coaster (10pcs)",
      "description": "Our 95mm circle coasters are printed in full color and made from thick, premium coaster board.",
      "price": 19.99,
      "deluxePrice": 19.99,
      "image": "coaster.jpg",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 35,
      "name": "OWASP Snakes and Ladders - Web Applications",
      "description": "This amazing web application security awareness board game is <a href=\"https://steamcommunity.com/sharedfiles/filedetails/?id=1969196030\">available for Tabletop Simulator on Steam Workshop</a> now!",
      "price": 0.01,
      "deluxePrice": 0.01,
      "image": "snakes_ladders.jpg",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 36,
      "name": "OWASP Snakes and Ladders - Mobile Apps",
      "description": "This amazing mobile app security awareness board game is <a href=\"https://steamcommunity.com/sharedfiles/filedetails/?id=1970691216\">available for Tabletop Simulator on Steam Workshop</a> now!",
      "price": 0.01,
      "deluxePrice": 0.01,
      "image": "snakes_ladders_m.jpg",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 37,
      "name": "OWASP Juice Shop Holographic Sticker",
      "description": "Die-cut holographic sticker. Stand out from those 08/15-sticker-covered laptops with this shiny beacon of 80's coolness!",
      "price": 2,
      "deluxePrice": 2,
      "image": "holo_sticker.png",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 38,
      "name": "OWASP Juice Shop \"King of the Hill\" Facemask",
      "description": "Facemask with compartment for filter from 50% cotton and 50% polyester.",
      "price": 13.49,
      "deluxePrice": 13.49,
      "image": "fan_facemask.jpg",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 41,
      "name": "Juice Shop \"Permafrost\" 2020 Edition",
      "description": "Exact version of <a href=\"https://github.com/juice-shop/juice-shop/releases/tag/v9.3.1-PERMAFROST\">OWASP Juice Shop that was archived on 02/02/2020</a> by the GitHub Archive Program and ultimately went into the <a href=\"https://github.blog/2020-07-16-github-archive-program-the-journey-of-the-worlds-open-source-code-to-the-arctic\">Arctic Code Vault</a> on July 8. 2020 where it will be safely stored for at least 1000 years.",
      "price": 9999.99,
      "deluxePrice": 9999.99,
      "image": "permafrost.jpg",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 42,
      "name": "Best Juice Shop Salesman Artwork",
      "description": "Unique digital painting depicting Stan, our most qualified and almost profitable salesman. He made a succesful carreer in selling used ships, coffins, krypts, crosses, real estate, life insurance, restaurant supplies, voodoo enhanced asbestos and courtroom souvenirs before <em>finally</em> adding his expertise to the Juice Shop marketing team.",
      "price": 5000,
      "deluxePrice": 5000,
      "image": "artwork2.jpg",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 43,
      "name": "OWASP Juice Shop Card (non-foil)",
      "description": "Mythic rare <em>(obviously...)</em> card \"OWASP Juice Shop\" with three distinctly useful abilities. Alpha printing, mint condition. A true collectors piece to own!",
      "price": 1000,
      "deluxePrice": 1000,
      "image": "card_alpha.jpg",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 45,
      "name": "OWASP Juice Shop LEGO™ Tower",
      "description": "Want to host a Juice Shop CTF in style? Build <a href=\"https://github.com/OWASP/owasp-swag/blob/master/projects/juice-shop/lego/OWASP%20JuiceShop%20Pi-server%201.2.pdf\" target=\"_blank\">your own LEGO™ tower</a> which holds four Raspberry Pi 4 models with PoE HAT modules <a href=\"https://github.com/juice-shop/multi-juicer/blob/main/guides/raspberry-pi/raspberry-pi.md\" target=\"_blank\">running a MultiJuicer Kubernetes cluster</a>! Wire to a switch and connect to your network to have an out-of-the-box ready CTF up in no time!",
      "price": 799,
      "deluxePrice": 799,
      "image": "lego_case.jpg",
      "createdAt": "2026-06-17T04:56:59.936Z",
      "updatedAt": "2026-06-17T04:56:59.936Z",
      "deletedAt": null
    },
    {
      "id": 47,
      "name": "Pineapple Juice (1000ml)",
      "description": "Tropical refreshment from the finest sun-ripened pineapples.",
      "price": 2.99,
      "deluxePrice": 2.99,
      "image": "pineapple_juice.png",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 48,
      "name": "Melon Juice (1000ml)",
      "description": "Refreshing and sweet juice made from ripe melons.",
      "price": 2.49,
      "deluxePrice": 2.49,
      "image": "melon_juice.png",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 49,
      "name": "Grape Juice (1000ml)",
      "description": "Deep purple and full of antioxidants from selected grapes.",
      "price": 2.99,
      "deluxePrice": 2.99,
      "image": "grape_juice.png",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 50,
      "name": "Dragonfruit Juice (500ml)",
      "description": "Exotic and vibrant juice made from dragonfruit.",
      "price": 3.99,
      "deluxePrice": 3.99,
      "image": "dragonfruit_juice.png",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 51,
      "name": "Berry Juice (1000ml)",
      "description": "A delicious blend of fresh forest berries.",
      "price": 3.49,
      "deluxePrice": 3.49,
      "image": "berry_juice.png",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 52,
      "name": "Basil Smoothie",
      "description": "A unique blend of fresh basil and ginger for a healthy kick.",
      "price": 2.99,
      "deluxePrice": 2.99,
      "image": "basil_smoothie.png",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 53,
      "name": "Bragă (500ml)",
      "description": "Traditional Balkan drink made from fermented millet. Lightly sweet-sour, refreshing, and naturally energizing.",
      "price": 2.49,
      "deluxePrice": 2.49,
      "image": "braga.jpg",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 54,
      "name": "Elderflower Cordial (500ml)",
      "description": "Floral and fragrant soft drink made from elderflowers. Traditionally enjoyed chilled.",
      "price": 3.29,
      "deluxePrice": 3.29,
      "image": "elderflower_cordial.jpg",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 55,
      "name": "Sea Buckthorn Juice (500ml)",
      "description": "Tangy and slightly sour juice, extremely rich in Vitamin C and antioxidants.",
      "price": 3.99,
      "deluxePrice": 3.99,
      "image": "sea_buckthorn_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    },
    {
      "id": 56,
      "name": "Pomegranate Drink (500ml)",
      "description": "A sweet and tart refreshment inspired by classic grenadine flavors.",
      "price": 4.49,
      "deluxePrice": 4.49,
      "image": "pomegranate_drink.jpg",
      "createdAt": "2026-06-17T04:56:59.937Z",
      "updatedAt": "2026-06-17T04:56:59.937Z",
      "deletedAt": null
    }
  ]
}
```
- Container uptime: 
```
CONTAINER ID   IMAGE                           COMMAND                  CREATED       STATUS       PORTS                      NAMES
fe313aa24257   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   2 hours ago   Up 2 hours   127.0.0.1:3000->3000/tcp   juice-shop
```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes
- Product listing/search present: [x] Yes
- Admin or account area discoverable: [x] Yes — notes: Account menu visible in the top-right; admin pages are reachable when an admin token is used.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No persistent JavaScript console errors during normal browsing. Submitting crafted inputs to the login endpoint produced a server-side 500 error (see images/image.png), indicating server-side error handling issues rather than client-side JS errors.
- Pre-populated local storage / cookies: none observed for unauthenticated sessions (checked Application -> Local Storage / Cookies)

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
% Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
  0   9903   0      0   0      0      0      0                              0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 16 Jun 2026 15:22:44 GMT
ETag: W/"26af-19ed1071c3f"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Tue, 16 Jun 2026 17:25:56 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **A01 — Broken Access Control** — The `/api/Products` endpoint returns product data without authentication, and an admin token allowed access to `/api/Users` which returned user data. These behaviors indicate missing or inadequate authorization checks and map to OWASP Top 10:2025 A01.
2. **A04 — Injection** — The login form accepts input that appears to be interpreted by the server (tested using payloads like `' OR 1=1 --`), which produced a 500 and in some probes allowed bypassing normal auth logic. This is consistent with SQL injection and maps to A04 (Injection).
3. **A10 — Mishandling of Exceptional Conditions** — Supplying malformed or unexpected input to the login endpoint triggers a 500 internal server error and verbose responses that reveal application behavior. The application fails-open or leaks implementation details on error paths, which corresponds to A10 in the OWASP Top 10:2025.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (feat(labN): <topic> style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes - since this file is absent in main repository, description will be not uploaded automatically [(link to draft PR)](https://github.com/StefFashka/DevSecOps-Intro/pull/1)

## GitHub Community

Starring repositories helps signal useful projects, supports maintainers, and keeps a personal shortlist of tools relevant to course work. Following instructors, TAs, and classmates improves visibility into practical workflows and makes collaboration faster in team assignments.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): https://github.com/StefFashka/DevSecOps-Intro/actions/runs/27681432984/job/81869588227
- Workflow run duration: 15s
- Curl response excerpt:
  ```
  HTTP/1.1 200 OK
  ```