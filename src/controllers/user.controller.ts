import { Body, Controller, Delete, Get, HttpStatus, Param, Post, UploadedFiles, Put, Req, Res } from "@nestjs/common";
import { User } from "../model/user.schema";
import { JwtService } from '@nestjs/jwt'
import { UserService } from "src/services/user.service";
@Controller('user')
export class UserController {
    constructor(private readonly userServerice: UserService,
        private jwtService: JwtService
    ) { }

    @Post('/signup')
    async Signup(@Res() response, @Body() user: User) {
        const newUSer = await this.userServerice.signup(user);
        return response.status(HttpStatus.CREATED).json('User created successfully');
    }

    @Post('/signin')
    async SignIn(@Res() response, @Body() user: User) {
        const token = await this.userServerice.signin(user, this.jwtService);
        return response.status(HttpStatus.OK).json(token)
    }

    //YOUTUBE PART

    @Post('/youtube/token')
    //first time user is authenticated with youtube api(he allows our project to use his data)
    async createToken(@Res() response) {
        const token = await this.userServerice.createToken();
        return response.status(HttpStatus.OK).json(token)
    }

    @Post('/youtube/getChannel')
    async getChannel(@Res() response, @Req() req,) {
        const channel = await this.userServerice.getChannel();
        return response.status(HttpStatus.OK).json(channel);
    }


    //INSTAGRAM PART

    @Get('/instagram/token')
    async createTokenInsta(@Res() response) {
        await this.userServerice.createTokenInsta(response);
    }

    @Get('/instagram/shortcode')
    async createShortTokenInsta(@Res() response) {
        await this.userServerice.getShortLivedAccessToken();
    }

    @Get('/instagram/longcode')
    async createLongTokenInsta(@Res() response) {
        await this.userServerice.getLongLivedAccessToken();
    }

      @Get('/instagram/profile')
    async getProfile(@Res() response) {
          await this.userServerice.getInstagramProfile(response);
    }


    



}