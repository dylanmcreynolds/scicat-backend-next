import {
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { InjectModel } from "@nestjs/mongoose";
import { FilterQuery, Model } from "mongoose";
import { CreatePolicyDto } from "./dto/create-policy.dto";
import { UpdatePolicyDto } from "./dto/update-policy.dto";
import { Policy, PolicyDocument } from "./schemas/policy.schema";
import { Request } from "express";
import { JWTUser } from "src/auth/interfaces/jwt-user.interface";
import { UsersService } from "src/users/users.service";
import { DatasetsService } from "src/datasets/datasets.service";
import { IPolicyFilter } from "./interfaces/policy-filters.interface";

@Injectable()
export class PoliciesService {
  constructor(
    private configService: ConfigService,
    private datasetsService: DatasetsService,
    @InjectModel(Policy.name) private policyModel: Model<PolicyDocument>,
    private usersService: UsersService,
  ) {}

  async create(createPolicyDto: CreatePolicyDto): Promise<Policy> {
    const createdPolicy = new this.policyModel(createPolicyDto);
    return createdPolicy.save();
  }

  async findAll(filter: IPolicyFilter): Promise<Policy[]> {
    const whereFilter: FilterQuery<PolicyDocument> = filter.where ?? {};
    let limit = 100;
    let skip = 0;
    let sort = {};
    if (filter.limit) {
      limit = filter.limit;
    }
    if (filter.skip) {
      skip = filter.skip;
    }
    if (filter.order) {
      const [field, direction] = filter.order.split(":");
      sort = { [field]: direction };
    }
    return this.policyModel
      .find(whereFilter)
      .limit(limit)
      .skip(skip)
      .sort(sort)
      .exec();
  }

  async count(where: FilterQuery<PolicyDocument>): Promise<{ count: number }> {
    const count = await this.policyModel.count(where).exec();
    return { count };
  }

  async findOne(filter: FilterQuery<PolicyDocument>): Promise<Policy | null> {
    return this.policyModel.findOne(filter).exec();
  }

  async update(
    filter: FilterQuery<PolicyDocument>,
    updatePolicyDto: UpdatePolicyDto,
  ): Promise<Policy | null> {
    return this.policyModel
      .findOneAndUpdate(filter, updatePolicyDto, { new: true })
      .exec();
  }

  async remove(filter: FilterQuery<PolicyDocument>): Promise<unknown> {
    return this.policyModel.findOneAndRemove(filter).exec();
  }

  async updateWhere(
    ownerGroupList: string,
    data: UpdatePolicyDto,
    req: Request,
  ) {
    if (!ownerGroupList) {
      throw new InternalServerErrorException(
        "Invalid ownerGroupList parameter",
      );
    }

    const ownerGroups = ownerGroupList
      .split(",")
      // eslint-disable-next-line @typescript-eslint/quotes
      .map((ownerGroup) => ownerGroup.trim().replace(new RegExp('"', "g"), ""));
    if (!ownerGroups) {
      throw new InternalServerErrorException(
        "Invalid ownerGroupList parameter",
      );
    }

    const userId = (req.user as JWTUser)._id;
    const userIdentity = await this.usersService.findByIdUserIdentity(userId);
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundException();
    }

    await Promise.all(
      ownerGroups.map(async (ownerGroup) => {
        const email = userIdentity ? userIdentity.profile.email : user.email;

        try {
          await this.addDefaultPolicy(ownerGroup, [], email, "low", req);
        } catch (error) {
          throw new InternalServerErrorException();
        }

        if (!userIdentity) {
          try {
            // allow all functional users
            await this.policyModel
              .updateOne({ ownerGroup }, data, { new: true })
              .exec();
          } catch (error) {
            throw new InternalServerErrorException();
          }
        } else {
          const hasPermission = await this.validatePermission(
            ownerGroup,
            userIdentity.profile.email,
          );
          if (!hasPermission) {
            Logger.error("Validation failed", "PoliciesService.updateWhere");
            throw new UnauthorizedException(
              "User not authorised for action based on policy",
            );
          }

          try {
            await this.policyModel
              .updateOne({ ownerGroup }, data, { new: true })
              .exec();
          } catch (error) {
            throw new InternalServerErrorException();
          }
        }
      }),
    );
  }

  async addDefaultPolicy(
    ownerGroup: string,
    accessGroups: string[],
    ownerEmail: string,
    tapeRedundancy: string,
    req: Request,
  ) {
    const policy = await this.policyModel.findOne({ ownerGroup }).exec();

    if (policy) {
      return;
    }

    Logger.log("Adding default policy", "PoliciesService.addDefaultPolicy");

    const defaultManager = this.configService.get<string[]>("defaultManager");
    const defaultPolicy: CreatePolicyDto = {
      ownerGroup,
      accessGroups,
      manager: ownerEmail
        ? ownerEmail.split(",")
        : defaultManager
        ? defaultManager
        : [""],
      tapeRedundancy: tapeRedundancy ? tapeRedundancy : "low",
      autoArchive: false,
      autoArchiveDelay: 7,
      archiveEmailNotification: true,
      retrieveEmailNotification: true,
      archiveEmailsToBeNotified: [],
      retrieveEmailsToBeNotified: [],
      embargoPeriod: 3,
      createdBy: req.user ? (req.user as JWTUser).username : "",
      updatedBy: req.user ? (req.user as JWTUser).username : "",
    };

    try {
      await this.create(defaultPolicy);
    } catch (error) {
      throw new InternalServerErrorException(
        error,
        "Error when creating default policy",
      );
    }

    await this.datasetsService.keepHistory(req);
  }

  async validatePermission(
    ownerGroup: string,
    email: string,
  ): Promise<boolean> {
    const policy = await this.policyModel.findOne({ ownerGroup }).exec();

    if (!policy) {
      return false;
    }

    if (policy.manager.includes(email)) {
      return true;
    }

    return false;
  }
}
