import { Injectable, HttpException, HttpStatus, Res } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User, UserDocument } from "../model/user.schema";
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { google } from 'googleapis';
var FormData = require('form-data');
const axios = require('axios');
var OAuth2 = google.auth.OAuth2;
var readline = require('readline');

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User.name) private userModel: Model<UserDocument>,

    ) {

    }

    async signup(user: User): Promise<User> {
        const salt = await bcrypt.genSalt();
        const hash = await bcrypt.hash(user.password, salt);
        const reqBody = {
            email: user.email,
            password: hash
        }
        const newUser = new this.userModel(reqBody);
        return newUser.save();
    }

    async signin(user: User, jwt: JwtService): Promise<any> {
        const foundUser = await this.userModel.findOne({ email: user.email }).exec();
        if (foundUser) {
            const { password } = foundUser;
            if (bcrypt.compare(user.password, password)) {
                const payload = { email: user.email, id: user.id };
                return {
                    token: jwt.sign(payload),
                };
            }
            return new HttpException('Incorrect email or password', HttpStatus.UNAUTHORIZED)
        }
        return new HttpException('Incorrect email or password', HttpStatus.UNAUTHORIZED)
    }

    async getOne(email): Promise<User> {
        return await this.userModel.findOne({ email }).exec();
    }


    //youtube part

    async createToken() {

        var clientSecret = process.env.ClientSecret;
        var clientId = process.env.ClientId;
        var redirectUrl = 'http://127.0.0.1:5500';

        //the oauth2Client object is used to make API calls
        //the redirect_uris is the url that the user will be redirected to after the login and should be added to the google developer console
        var oauth2Client = new OAuth2(clientId, clientSecret, redirectUrl);

        var authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: ['https://www.googleapis.com/auth/youtube']
        });
        console.log('Authorize this app by visiting this url: ', authUrl);
        var rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        rl.question('Enter the code from that page here: ', function (code) {
            rl.close();
            oauth2Client.getToken(code, function (err, token) {
                if (err) {
                    console.log('Error while trying to retrieve access token', err);
                    return;
                }
                oauth2Client.credentials = token;
                //the token is stored in the oauth2Client object
                //it contains refresh and access token
                //it can be used to make api calls
                //refresh token can be used to generate a new access token
                //refresh token never expires I recommend storing it in a database
                console.log(token);
                return token;
            });
        });

    }

    async tokenInfo(access_token, refresh_token) {
        var clientSecret = process.env.ClientSecret;
        var clientId = process.env.ClientId;
        var redirectUrl = 'http://127.0.0.1:5500';

        var oauth2Client = new OAuth2(clientSecret, clientId, redirectUrl);

        //info for current access token
        const tokenInfo = await oauth2Client.getTokenInfo(access_token);

        //current access token expiration time
        const expireDate = new Date(tokenInfo.expiry_date);

        if (expireDate < new Date()) {
            console.log('Token expired');
            await axios({
                method: "post",
                url: "https://oauth2.googleapis.com/token",
                body: {
                    client_id: clientId,
                    client_secret: clientSecret,
                    refresh_token: refresh_token,
                    grant_type: "refresh_token"
                },
            }).then((response) => {
                console.log(response.data);

            })
        }
        else {
            return access_token;
        }
    }
    /**
     *
     *
     * @param {google.auth.OAuth2} auth An authorized OAuth2 client.
     */
    async getChannel() {
        var service = google.youtube('v3');

        //check the last used access token info to see if it is still valid
        //the access token might be saved in a database or redis and is related to a user
        //if not, tokenInfo generates a new access token
        let access_token, refresh_token;
        //this values should be found from database or redis
        var auth = await this.tokenInfo(access_token, refresh_token);


        await axios({
            method: "get",
            url: "https://www.googleapis.com/youtube/v3/channels/?mine=true&auth=AIzaSyDbgFZPmKEunOmw65-YkqNA0ljcnJ1CSr4&part[]=snippet",
            headers: {
                Authorization: `Bearer + ${auth}`,
            },
        }).then((response) => {
            //this user does not have a channel
            if (response.data.pageInfo.totalResults === 0) {
                return false;
            }

            const channelId = response.data.items[0].id;

            service.channels.list({
                //auth is the api key for youtube api v3
                auth: process.env.YouTubeAPI,
                part: ['snippet,contentDetails,statistics'],
                id: [channelId]
            }, function (err, response) {
                if (err) {
                    console.log('The API returned an error: ' + err);
                    return;
                }
                var channels = response.data.items;
                if (channels.length == 0) {
                    console.log('No channel found.');
                } else {
                    console.log('This channel\'s ID is %s. Its title is \'%s\', and ' +
                        'it has %s views.',
                        channels[0].id,
                        channels[0].snippet.title,
                        channels[0].statistics.viewCount);
                }
            });

        });
    }


    //instagram part
    async createTokenInsta(@Res() response) {
      
        const url = `https://api.instagram.com/oauth/authorize?client_id=${process.env.ClientId}&redirect_uri=https://httpstat.us/200&scope=user_media,user_profile&response_type=code`
        console.log('Authorize this app by visiting this url: ', `${url}`);
        var rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        rl.question('Enter the code from that page here: ', function (code) {
            const insta_code = code;
            rl.close();
        });

    };

    async getShortLivedAccessToken() {
        var bodyFormData = new FormData();
        bodyFormData.append('client_id', process.env.ClientId);
        bodyFormData.append('client_secret',    process.env.ClientSecret);
        bodyFormData.append('redirect_uri', "https://httpstat.us/200");
        bodyFormData.append('code', 'AQDWwxjGUHb5aeothIMBh9-wm-FWYwhpUwXLCdEwN8LrOZ2k28lk37VrxO3Q2Y8tzhQhZiUdFnVLEZP4YHUad6r8Rm-De1nGVdVnJ4HNJdfdl06xk6lrCzKd9qVEkLFDuljQjm04SXIlloZMJ7TsJHVnZSUH47Wde--F6rvFnrAXYrwCPd5PZoMliwJwu2_NvapVwrrOfqPoEeyKcPMJp2I2W1pNbPxAF1SfqkCcS61x_w');
        bodyFormData.append('grant_type', "authorization_code");

        await axios({
            method: "post",
            url: "https://api.instagram.com/oauth/access_token",
            data: bodyFormData,
            headers: { "Content-Type": "multipart/form-data", host: "api.instagram.com" },
        }).then((response) => {
            // getting the response.
            console.log(response.data);

        }).catch((error) => {
            // error handling.
            console.log(error);
        });
    }

    async getLongLivedAccessToken() {
        try {
            // send a request to the API
            await axios.get("https://graph.instagram.com/access_token", {
                params: {
                    grant_type: "ig_exchange_token",
                    client_secret: process.env.ClientSecretInsta,
                    access_token: 'accesstoken',
                },
            }).then((response) => {
                // getting the response.
                //returns access token which is valid for 60 days
                //you can save this token in your database with expiration time Date.now + 59 days
                //refreshing access token is managed with a cron job , which is set to run every day at 9:00 am
                //check for access tokens in the database and refresh them if they are ready to expire

                console.log(response.data);

            }).catch((error) => {
                // error handling.
                console.log(error);
            });
        } catch (error) {
            // If an error occurs, return it.
            console.log(error);

        }
    }

    async getInstagramProfile(response) {
        try {
            console.log("Getting profile");

            // send a request to the API
            await axios.get("https://graph.instagram.com/me", {
                params: {
                    fields: "id,username,media_count,account_type",
                    access_token: "access token",
                },
                headers: {
                    host: "graph.instagram.com",
                },
            }).then(async (response) => {
                console.log(response.data);
                const A = await axios.get(`https://www.instagram.com/${response.data.username}/?__a=1`);
                console.log(A.data);
            }).catch((error) => {
                // error handling.
                console.log(error);
            });
        } catch (error) {
            // If an error occurs, return it.
            console.log(error);

        }
    }

}
