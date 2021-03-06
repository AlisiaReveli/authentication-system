import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
export type UserDocument = User & Document;
@Schema()
export class User {
    @Prop()
    id?: string;

    @Prop({ required: true, unique: true, lowercase: true })
    email: string;

    @Prop({ required: true })
    password: string

    @Prop({ required: false })
    refresh_token: string


    @Prop({ default: Date.now() })
    createdDate?: Date
}
export const UserSchema = SchemaFactory.createForClass(User)