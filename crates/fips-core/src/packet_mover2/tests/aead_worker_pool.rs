    #[test]
    fn aead_worker_pool_executes_stateless_jobs_before_owner_retire() {
        let owner = OwnerId::fmp(90);
        let key = 9;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(20));

        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(90, 1, 0, b"inbound", key),
                )
                .unwrap(),
            )
            .unwrap();
        mover
            .submit_outbound_packet(outbound_packet(
                owner,
                1,
                PacketClass::Bulk,
                b"outbound",
            ))
            .unwrap();

        let mut open_work = mover.dispatch_available(8);
        let mut seal_work = mover.dispatch_outbound_available(8);
        assert_eq!(open_work.len(), 1);
        assert_eq!(seal_work.len(), 1);

        let mut jobs = vec![
            PacketMover2AeadJob::Open {
                work: open_work.pop().unwrap(),
                cipher: test_key(key),
            },
            PacketMover2AeadJob::Seal {
                work: seal_work.pop().unwrap(),
                cipher: test_key(key),
            },
        ];
        let mut completions = Vec::new();
        packet_mover2_aead_pool().execute_jobs_into(&mut jobs, &mut completions);
        assert!(jobs.is_empty());
        assert_eq!(completions.len(), 2);

        let mut retired = Vec::new();
        for completion in completions {
            retired.extend(mover.retire_completion(completion));
        }
        let mut outputs = outputs(retired);
        outputs.sort_by_key(PacketOutput::counter);

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].counter, 1);
        assert_eq!(&outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..], b"inbound");
        assert_eq!(outputs[1].counter, 20);
        assert_eq!(open_sealed_output(&outputs[1], key), b"outbound");
    }
