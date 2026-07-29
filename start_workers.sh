#!/bin/bash
nohup rq worker --worker-class rq.worker.SimpleWorker --url redis://localhost:6379 > /tmp/rq_default.log 2>&1 &
nohup rq worker ia --worker-class rq.worker.SimpleWorker --url redis://localhost:6379 > /tmp/rq_ia.log 2>&1 &
nohup rq worker osint --worker-class rq.worker.SimpleWorker --url redis://localhost:6379 > /tmp/rq_osint.log 2>&1 &