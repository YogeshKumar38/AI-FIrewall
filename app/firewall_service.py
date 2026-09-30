import time

from src.pipeline import AIFirewall
from llm.gemini_gateway import GeminiGateway
from audit_logging.security_logger import SecurityLogger


class FirewallService:

    def __init__(self):
        self.firewall = AIFirewall()
        self.gemini = GeminiGateway()
        self.logger = SecurityLogger()

    def process(self, prompt: str):

        start_time = time.perf_counter()

        # 1. Analyze prompt with AI Firewall
        result = self.firewall.analyze(prompt)

        # 2. Log security decision
        self.logger.log(
            result
        )

        # 3. Only ALLOW can reach Gemini
        if result.decision != "ALLOW":
            return {
                "firewall_result": result.to_dict(),
                "llm_response": None,
                "llm_called": False,
                "processing_time_ms": (
                    time.perf_counter() - start_time
                ) * 1000,
            }

        # 4. Send allowed prompt to Gemini
        response = self.gemini.generate(prompt)

        return {
            "firewall_result": result.to_dict(),
            "llm_response": response,
            "llm_called": True,
            "processing_time_ms": (
                time.perf_counter() - start_time
            ) * 1000,
        }