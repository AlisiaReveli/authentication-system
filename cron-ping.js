const cron = require('node-cron');
cron.schedule('0 9 * * *', function() {
  console.log('running a task every day at 9 am');
  //check on database for access tokens ready to be expired
        await axios.get('https://graph.instagram.com/refresh_access_token', {
            params: {
                grant_type: 'ig_refresh_token',
                access_token: "IGQVJWV1doam1hYXFHbWNuaUd0TWhmOUJ2bldYeHJkY0NldWFIU0xBT2pjMERHWnlJTXNvYTl2TVdoaGRwc3Btal9SNkVhX1VVbmdaaTNfWlN0cF8xRk1FbmVkRnJSODh5QkJoN21R",
            },
            headers: {
                host: "graph.instagram.com",
            },
        }).then(async (response) => {
            console.log(response.data);
        }).catch((error) => {
            // error handling.
            console.log(error);
        });

});