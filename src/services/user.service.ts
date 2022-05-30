import { Injectable, HttpException, HttpStatus } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User, UserDocument } from "../model/user.schema";
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { google } from 'googleapis';
const axios = require('axios');
var OAuth2 = google.auth.OAuth2;
var readline = require('readline');

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User.name) private userModel: Model<UserDocument>,

    ) { }

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

    async createToken(credentials) {
        var clientSecret = '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';
        var clientId = '283565823112-trtrv2v5clvdmc026hekbmc1s47ii3o4.apps.googleusercontent.com';
        var redirectUrl = 'http://127.0.0.1:5500';
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
                return token;
                // callback(oauth2Client);
            });
        });

    }
    /**
     * Lists the names and IDs of up to 10 files.
     *
     * @param {google.auth.OAuth2} auth An authorized OAuth2 client.
     */
    async getChannel() {
        var service = google.youtube('v3');

        const hasChannel = await axios({
            method: "get",
            url: "https://www.googleapis.com/youtube/v3/channels/?mine=true&auth=AIzaSyDbgFZPmKEunOmw65-YkqNA0ljcnJ1CSr4&part[]=snippet",
            headers: {
                Authorization: `Bearer ya29.a0ARrdaM_k4edvwjgLCbLbomGv1Hq4rG6deTVahOI8wWIMahnAS-Mclf0lS3dH_e6Mpff8WN-Rz9u_N1WFkR_kWEVTPTSi1_Q3UB6Aj3HqiAG86HDgqzrSPhc9WNPyAVsik0twEMKE4TthaLEeKTWdqqauZskS`,
            },
        }).then((response) => {
            if (response.data.pageInfo.totalResults === 0) {
                return false;
            }

            const channelId = response.data.items[0].id;

            service.channels.list({
                auth: 'AIzaSyDbgFZPmKEunOmw65-YkqNA0ljcnJ1CSr4',
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
}
