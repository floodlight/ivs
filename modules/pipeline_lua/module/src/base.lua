-- To be overridden by uploaded code
function ingress() end

-- Entrypoint for packet processing
function process()
    ingress()
end
