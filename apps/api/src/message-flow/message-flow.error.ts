import { machineErrorContractVersion } from '@kovcheg/contracts';
import type { CorrelationId, MachineError, MessageFlowErrorCode } from '@kovcheg/contracts';
import { HttpException } from '@nestjs/common';

export class MessageFlowHttpError extends HttpException {
  constructor(
    code: MessageFlowErrorCode,
    correlationId: CorrelationId,
    httpStatus: number,
    title: string,
  ) {
    const error: MachineError = Object.freeze({
      code,
      contractVersion: machineErrorContractVersion,
      correlationId,
      httpStatus,
      title,
    });
    super(error, httpStatus);
  }
}
