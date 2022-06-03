local tcpls_proto = Proto("TCPLS", "TCPLS")
local tcpls_control_record = Proto("TCPLS_Control", "TCPLS Control")
local tcpls_extensions = Proto("TCPLS_Extentions", "TCPLS Extensions")

function append_info(pktinfo, text)
    local t = tostring(pktinfo.cols.info)
    if not t:match("(info)") and t:len() > 0 then
        pktinfo.cols.info:append(", ")
    end
    pktinfo.cols.info:append(text)
end

function tcpls_proto.init()
end

tcpls_proto.fields = {}

function tcpls_proto.dissector(tvbuf, pktinfo, root)
end

function tcpls_control_record.init()
end

local tcpls_control_message_types = {
    [ 0] = "NONE",
    [ 1] = "CONTROL_VARLEN_BEGIN",
    [ 2] = "BPF_CC",
    [ 3] = "CONNID",
    [ 4] = "COOKIE",
    [ 5] = "DATA_ACK",
    [ 6] = "FAILOVER",
    [ 7] = "FAILOVER_END",
    [ 8] = "MPJOIN",
    [ 9] = "MULTIHOMING_v6",
    [10] = "MULTIHOMING_v4",
    [11] = "USER_TIMEOUT",
    [12] = "STREAM_ATTACH",
    [13] = "STREAM_CLOSE",
    [14] = "STREAM_CLOSE_ACK",
    [15] = "TRANSPORT_NEW",
    [16] = "TRANSPORT_UPDATE",
}

local tcpls_control_message_type = ProtoField.uint32("tcpls.record.type", "Message Type", base.DEC, tcpls_control_message_types, nil, "TCPLS Control Message Type")
local tcpls_control_stream_attach_stream_id = ProtoField.uint32("tcpls.stream_attach.stream_id", "Stream ID", base.DEC, nil, nil, "TCPLS Stream Attach Stream ID")
local tcpls_control_stream_attach_transport_id = ProtoField.uint32("tcpls.stream_attach.transport_id", "Transport ID", base.DEC, nil, nil, "TCPLS Stream Attach Stream ID")
local tcpls_control_stream_attach_offset = ProtoField.uint32("tcpls.stream_attach.offset", "Offset", base.DEC, nil, nil, "TCPLS Stream Attach Stream Offset")
local tcpls_control_stream_close_stream_id = ProtoField.uint32("tcpls.stream_close.stream_id", "Stream ID", base.DEC, nil, nil, "TCPLS Stream Close Stream ID")
local tcpls_control_stream_close_ack_stream_id = ProtoField.uint32("tcpls.stream_close_ack.stream_id", "Stream ID", base.DEC, nil, nil, "TCPLS Stream Close ACK Stream ID")

tcpls_control_record.fields = { tcpls_control_message_type,
                                tcpls_control_stream_attach_stream_id, tcpls_control_stream_attach_transport_id, tcpls_control_stream_attach_offset,
                                tcpls_control_stream_close_stream_id,
                                tcpls_control_stream_close_ack_stream_id
}


function tcpls_control_record.dissector(tvbuf, pktinfo, root)
    pktinfo.cols.protocol:set("TCPLS")

    local pktlen = tvbuf:reported_length_remaining()
    local message_type_range = tvbuf:range(pktlen - 4, 4)
    local message_type = message_type_range:uint()
    local tree = root:add(string.format("TCPLS Control Record: %s", tcpls_control_message_types[message_type] or "Unknown"), tvbuf:range(0,pktlen))

    tree:add(tcpls_control_message_type, message_type_range)

    if message_type == 12 then
        tree:add(tcpls_control_stream_attach_stream_id, tvbuf:range(0, 4))
        tree:add(tcpls_control_stream_attach_transport_id, tvbuf:range(4, 4))
        tree:add(tcpls_control_stream_attach_offset, tvbuf:range(8, 4))
        append_info(pktinfo, tcpls_control_message_types[message_type] .. "(" .. tvbuf:range(0, 4):uint() .. ")")
    elseif message_type == 13 then
        tree:add(tcpls_control_stream_close_stream_id, tvbuf:range(0, 4))
        append_info(pktinfo, tcpls_control_message_types[message_type] .. "(" .. tvbuf:range(0, 4):uint() .. ")")
    elseif message_type == 14 then
        tree:add(tcpls_control_stream_close_ack_stream_id, tvbuf:range(0, 4))
        append_info(pktinfo, tcpls_control_message_types[message_type] .. "(" .. tvbuf:range(0, 4):uint() .. ")")
    end

    return pktlen
end

DissectorTable.get("tls.record"):add(26, tcpls_control_record)

function tcpls_extensions.init()
end

local tcpls_extensions_types = {
    [100] = "TCP Options",
    [101] = "TCP User Timeout",
    [102] = "Multihoming v4",
    [103] = "Multihoming v6",
    [104] = "TCPLS Connection ID",
    [105] = "TCPLS Cookie",
    [106] = "TCPLS MP Join",
}

local tcpls_extensions_type = ProtoField.uint32("tcpls.extension.type", "Type", base.DEC, tcpls_extensions_types, nil, "TCPLS Extension Type")
local tcpls_extensions_length = ProtoField.uint32("tcpls.extension.length", "Length", base.DEC, nil, nil, "TCPLS Extension Length")
local tcpls_multihoming_v4_addr = ProtoField.ipv4("tcpls.multihoming.v4_address", "v4 Address", ftypes.IPv4, nil, nil, "TCPLS Multihoming v4 Address")
local tcpls_multihoming_v6_addr = ProtoField.ipv6("tcpls.multihoming.v6_address", "v6 Address", ftypes.IPv6, nil, nil, "TCPLS Multihoming v6 Address")
local tcpls_cookie = ProtoField.bytes("tcpls.cookie", "Cookie", base.NONE, "TCPLS Cookie")
local tcpls_connection_id = ProtoField.bytes("tcpls.connection_id", "Connection ID", base.NONE, "TCPLS Connection ID")
local tcpls_mpjoin_cookie = ProtoField.bytes("tcpls.mpjoin.cookie", "MPJOIN Cookie", base.NONE, "TCPLS MPJOIN Cookie")
local tcpls_mpjoin_connection_id = ProtoField.bytes("tcpls.mpjoin.connection_id", "MPJOIN Connection ID", base.NONE, "TCPLS MPJOIN Connection ID")
local tcpls_mpjoin_transportid = ProtoField.uint32("tcpls.mpjoin.transportid", "MPJOIN Transport ID", base.DEC, nil, nil, "TCPLS MPJOIN Transport ID")
local tcpls_user_timeout = ProtoField.uint16("tcpls.user_timeout", "Timeout", base.HEX, nil, nil, "TCPLS User Timeout Value")

tcpls_extensions.fields = {
    tcpls_extensions_type,
    tcpls_extensions_length,
    tcpls_multihoming_v4_addr,
    tcpls_multihoming_v6_addr,
    tcpls_cookie,
    tcpls_connection_id,
    tcpls_user_timeout,
    tcpls_mpjoin_cookie,
    tcpls_mpjoin_connection_id,
    tcpls_mpjoin_transportid,
}


function tcpls_extensions.dissector(tvbuf, pktinfo, root)
    pktinfo.cols.protocol:set("TCPLS")

    local pktlen = tvbuf:reported_length_remaining()
    local extension_type_range = tvbuf:range(0, 2)
    local extension_type = extension_type_range:uint()
    local extension_len_range = tvbuf:range(2, 2)
    local extension_len = extension_len_range:uint()
    local tree = root:add(string.format("TCPLS Extension: %s", tcpls_extensions_types[extension_type] or "Unknown"), tvbuf:range(0,pktlen))

    tree:add(tcpls_extensions_type, extension_type_range)
    tree:add(tcpls_extensions_length, extension_len_range)

    if extension_type == 101 then
        tree:add(tcpls_user_timeout, tvbuf:range(4, 2))
    elseif extension_type == 102 then
        local addr_offset = 8;
        while addr_offset + 4 <= pktlen do
            tree:add(tcpls_multihoming_v4_addr, tvbuf:range(addr_offset, 4))
            addr_offset = addr_offset + 4
        end
    elseif extension_type == 103 then
        local addr_offset = 8;
        while addr_offset + 16 <= pktlen do
            tree:add(tcpls_multihoming_v6_addr, tvbuf:range(addr_offset, 16))
            addr_offset = addr_offset + 16
        end
    elseif extension_type == 104 then
        tree:add(tcpls_connection_id, tvbuf:range(7, pktlen - 7))
    elseif extension_type == 105 then
        tree:add(tcpls_cookie, tvbuf:range(7, pktlen - 7))
    elseif extension_type == 106 then
        tree:add(tcpls_mpjoin_connection_id, tvbuf:range(5, 16))
        tree:add(tcpls_mpjoin_transportid, tvbuf:range(21, 4))
        tree:add(tcpls_mpjoin_cookie, tvbuf:range(26, 16))
    end

    return pktlen
end

DissectorTable.get("tls.extensions"):add(100, tcpls_extensions)
DissectorTable.get("tls.extensions"):add(101, tcpls_extensions)
DissectorTable.get("tls.extensions"):add(102, tcpls_extensions)
DissectorTable.get("tls.extensions"):add(103, tcpls_extensions)
DissectorTable.get("tls.extensions"):add(104, tcpls_extensions)
DissectorTable.get("tls.extensions"):add(105, tcpls_extensions)
DissectorTable.get("tls.extensions"):add(106, tcpls_extensions)
