"""Image-owned, opt-in Registry candidate READ extension (not authoritative Desired).

No Registry listener, socket path, machine grant or WRITE exists on import.
A trusted R7 host composition must supply the already-verified AF_UNIX reader;
client/config payloads never choose Registry credentials, path or principal.
"""
from dataclasses import replace

from ...core import Denied
from ...extensions.model import Operation, Provider
from ...extensions.runtime import Context
from .candidate_gateway import GatewayRegistryUnixCandidateRead
from .read_contract import GATEWAY_TARGET, validate_gateway_read_query, validate_gateway_read_projection

_READS = ('candidate_head', 'candidate_list_desired', 'candidate_original_operation')


def _params(operation):
    def validate(value):
        validate_gateway_read_query(operation, GATEWAY_TARGET, value)
    return validate


def _result(operation):
    def validate(value):
        validate_gateway_read_projection(operation, value)
    return validate


def _execute(operation):
    def read(ctx):
        if (type(ctx) is not Context or ctx.phase != 'execute'
                or ctx.provider.name != 'registry'
                or ctx.operation.name != operation
                or ctx.target != GATEWAY_TARGET):
            raise Denied('REGISTRY_EXTENSION_CONTEXT_DENIED')
        reader = ctx.provider.api
        if type(reader) is not GatewayRegistryUnixCandidateRead:
            raise Denied('REGISTRY_EXTENSION_READER_UNBOUND')
        # Ensure this invocation is the exact Core-persisted and authenticated
        # DISPATCHED request, not a forged direct executor call.
        row = ctx.runtime.core._read(ctx.request_id)
        request = row['request']
        if (row['state'] != 'DISPATCHED'
                or row['actor'] != ctx.authenticated_actor
                or request['service'] != 'registry'
                or request['operation'] != operation
                or request['target'] != ctx.target
                or request['params'] != ctx.params
                or request['requestId'] != ctx.request_id):
            raise Denied('REGISTRY_EXTENSION_CORE_BINDING_DENIED')
        validate_gateway_read_query(operation, ctx.target, ctx.params)
        response = reader.read({
            'service': 'registry', 'operation': operation,
            'target': ctx.target, 'params': ctx.params,
            'requestId': ctx.request_id,
        })
        return validate_gateway_read_projection(operation, response)
    return read


# Image discovery is safe and fail-closed. A configured but unbound provider
# cannot be made executable merely by an owner DENY→ALLOW policy transition.
PROVIDER = Provider('registry', tuple(Operation(
    name, 'Source-only Registry candidate ' + name + ' (not live Desired)',
    'read', _params(name), _result(name), _execute(name),
    ready=False, allowed_targets=(GATEWAY_TARGET,),
) for name in _READS))


def bind_reader(packaged, reader):
    """Trusted host-only binding; never accepts public config or JSON dicts."""
    if (type(packaged) is not Provider or packaged.name != 'registry'
            or packaged.api is not None
            or tuple(packaged.operations) != PROVIDER.operations
            or type(reader) is not GatewayRegistryUnixCandidateRead):
        raise Denied('REGISTRY_EXTENSION_BINDING_DENIED')
    reader._check_identity()
    return replace(packaged, api=reader, operations=tuple(
        replace(op, ready=True) for op in packaged.operations))
