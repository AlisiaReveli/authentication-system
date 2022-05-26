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


    @Post('/youtube/token')
    async createToken(@Res() response, @Req() req,) {
        const credentials = {
            project_id: req.body.project_id,
            client_id: req.body.client_id,
            client_secret: req.body.client_secret,
            redirect_uris: req.body.redirect_uris,
        }
        const token = await this.userServerice.createToken(credentials);
        return response.status(HttpStatus.OK).json(token)
    }


}