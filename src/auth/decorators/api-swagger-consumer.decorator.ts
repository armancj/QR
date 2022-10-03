import {
  applyDecorators,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiHideProperty,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { ApiPaginatedResponse } from '../Model/api-paginated-response.model';
import { PaginationQueryDto } from '../dto/pagination-query.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { UserDeactivatedGuard } from '../../auth/guards/user-deactivated.guard';
import { EmailConfirmationGuard } from '../../auth/guards/email-confirmation.guard';

export const Auth = () => {
  return applyDecorators(
    UseGuards(
      JwtAuthGuard,
      RolesGuard,
      UserDeactivatedGuard,
      EmailConfirmationGuard,
    ),
    ApiBearerAuth(),
    ApiUnauthorizedResponse({ description: 'No autorizado' }),
    ApiForbiddenResponse({ description: 'Prohibido.' }),
  );
};

interface apiParams {
  /**
   * The collection method of the Api responses of swagger .
   */
  summary?: string;
  description_NotFound?: string;
  paginated?: boolean;
  description_Conflict?: string;
  enumAny?: string;
  queryAny?: any;
  api_body?: any;
  description_param?: string;
  description_param_type?: any;
  type?: any;
  description_okResponse?: string;
  description_create?: string;
  description_BadRequest?: boolean;
  api_res?: any;
}

export const ApiResponseCustom = (params?: apiParams) => {
  const isApplyApi_body = params
    ? params.api_body
      ? ApiBody({ type: params.api_body })
      : ApiHideProperty()
    : ApiHideProperty();

  const isApplyQuery = params
    ? params.enumAny && params.queryAny
      ? ApiQuery({ name: params.enumAny, enum: params.queryAny })
      : ApiHideProperty()
    : ApiHideProperty();

  const isApplyOkResponse = params
    ? params.description_okResponse
      ? ApiOkResponse({ description: params.description_okResponse })
      : ApiHideProperty()
    : ApiHideProperty();

  const isApplyCreate = params
    ? params.description_create || params.type
      ? ApiCreatedResponse({
          description: params.description_create,
          type: params.type,
        })
      : ApiHideProperty()
    : ApiHideProperty();

  const isApply_Conflict = params
    ? params.description_Conflict
      ? ApiConflictResponse({
          description: params.description_Conflict,
        })
      : ApiHideProperty()
    : ApiHideProperty();

  const isApply_NotFound = params
    ? params.description_NotFound
      ? ApiNotFoundResponse({
          description: params.description_NotFound,
        })
      : ApiHideProperty()
    : ApiHideProperty();

  const isApply_param = params
    ? params.description_param || params.description_param_type
      ? ApiParam({
          name: 'id',
          description: params.description_param,
          type: params.description_param_type,
        })
      : ApiHideProperty()
    : ApiHideProperty();

  const isApplyPaginated = params
    ? params.paginated === true
      ? ApiPaginatedResponse(PaginationQueryDto)
      : ApiHideProperty()
    : ApiHideProperty();

  const isApplySummary = params
    ? params.summary
      ? ApiOperation({ summary: params.summary })
      : ApiHideProperty()
    : ApiHideProperty();

  const IsApplyBadRequest = params
    ? params.description_BadRequest === true
      ? ApiBadRequestResponse({ description: 'Data pre-validation failed' })
      : ApiHideProperty
    : ApiHideProperty();

  const IsApplyUsePipe = params
    ? params.description_BadRequest === true
      ? UsePipes(ValidationPipe)
      : ApiHideProperty
    : ApiHideProperty();

  return applyDecorators(
    IsApplyBadRequest,
    isApply_Conflict,
    isApply_NotFound,
    isApplyOkResponse,
    isApplySummary,
    isApplyQuery,
    isApplyCreate,
    isApplyPaginated,
    isApply_param,
    isApplyApi_body,
    IsApplyUsePipe,
  );
};
