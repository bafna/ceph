// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2012 New Dream Network
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 */
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include "os/FileStore.h"
#include "common/ceph_argparse.h"
#include "global/global_init.h"
#include "common/debug.h"
#include <boost/scoped_ptr.hpp>
#include "workload_generator.h"

boost::scoped_ptr<WorkloadGenerator> wrkldgen;
const coll_t WorkloadGenerator::META_COLL("meta");
const coll_t WorkloadGenerator::TEMP_COLL("temp");

WorkloadGenerator::WorkloadGenerator(vector<const char*> args) :
    m_allow_coll_destruction(false),
    m_prob_destroy_coll(def_prob_destroy_coll),
    m_prob_create_coll(def_prob_create_coll),
    m_num_colls(def_num_colls), m_num_obj_per_coll(def_num_obj_per_coll),
    m_store(0), m_in_flight(0), m_lock("State Lock") {

  init_args(args);
  dout(0) << "data         = " << g_conf->osd_data << dendl;
  dout(0) << "journal      = " << g_conf->osd_journal << dendl;
  dout(0) << "journal size = " << g_conf->osd_journal_size << dendl;

  ::mkdir(g_conf->osd_data.c_str(), 0755);
  ObjectStore *store_ptr = new FileStore(g_conf->osd_data, g_conf->osd_journal);
  m_store.reset(store_ptr);
  m_store->mkfs();
  m_store->mount();

  m_osr.resize(m_num_colls);

  init();
}

void WorkloadGenerator::init_args(vector<const char*> args) {
  for (std::vector<const char*>::iterator i = args.begin(); i != args.end();) {
    string val;
    int allow_coll_dest;

    if (ceph_argparse_double_dash(args, i)) {
      break;
    } else if (ceph_argparse_witharg(args, i, &val, "-C", "--num-collections",
        (char*) NULL)) {
      m_num_colls = strtoll(val.c_str(), NULL, 10);
    } else if (ceph_argparse_witharg(args, i, &val, "-O", "--num-objects",
        (char*) NULL)) {
      m_num_obj_per_coll = strtoll(val.c_str(), NULL, 10);
    } else if (ceph_argparse_binary_flag(args, i, &allow_coll_dest, NULL,
        "--allow-coll-destruction", (char*) NULL)) {
      m_allow_coll_destruction = (allow_coll_dest ? true : false);
    }
  }
}

void WorkloadGenerator::init() {

  dout(0) << "Initializing..." << dendl;

  ObjectStore::Transaction *t = new ObjectStore::Transaction;

  t->create_collection(META_COLL);
  t->create_collection(TEMP_COLL);
  m_store->apply_transaction(*t);

  wait_for_ready();

  char buf[100];
  for (int i = 0; i < m_num_colls; i++) {
    memset(buf, 0, 100);
    snprintf(buf, 100, "0.%d_head", i);
    coll_t coll(buf);

    dout(0) << "Creating collection " << coll.to_str() << dendl;

    t = new ObjectStore::Transaction;

    t->create_collection(coll);

    memset(buf, 0, 100);
    snprintf(buf, 100, "pglog_0.%d_head", i);
    hobject_t coll_meta_obj(sobject_t(object_t(buf), CEPH_NOSNAP));
    t->touch(META_COLL, coll_meta_obj);

    m_store->queue_transaction(&m_osr[i], t,
        new C_WorkloadGeneratorOnReadable(this, t));
    m_in_flight++;
  }

  wait_for_done();
  dout(0) << "Done initializing!" << dendl;
}

int WorkloadGenerator::get_random_collection_nr() {
  return (rand() % m_num_colls);
}

int WorkloadGenerator::get_random_object_nr(int coll_nr) {
  return ((rand() % m_num_obj_per_coll) + (coll_nr * m_num_obj_per_coll));
}

coll_t WorkloadGenerator::get_collection_by_nr(int nr) {
  char buf[100];
  memset(buf, 0, 100);

  snprintf(buf, 100, "0.%d_head", nr);
  return coll_t(buf);
}

hobject_t WorkloadGenerator::get_object_by_nr(int nr) {
  char buf[100];
  memset(buf, 0, 100);
  snprintf(buf, 100, "%d", nr);

  return hobject_t(sobject_t(object_t(buf), CEPH_NOSNAP));
}

hobject_t WorkloadGenerator::get_coll_meta_object(coll_t coll) {
  char buf[100];
  memset(buf, 0, 100);
  snprintf(buf, 100, "pglog_%s", coll.c_str());

  return hobject_t(sobject_t(object_t(buf), CEPH_NOSNAP));
}

/**
 * We'll generate a random amount of bytes, ranging from a single byte up to
 * a couple of MB.
 */
size_t WorkloadGenerator::get_random_byte_amount(size_t min, size_t max) {
  size_t diff = max - min;
  return (size_t) (min + (rand() % diff));
}

void WorkloadGenerator::get_filled_byte_array(bufferlist& bl, size_t size) {
  static const char alphanum[] = "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

  bufferptr bp(size);
  for (unsigned int i = 0; i < size - 1; i++) {
    bp[i] = alphanum[rand() % sizeof(alphanum)];
  }
  bp[size - 1] = '\0';
  bl.append(bp);
}

void WorkloadGenerator::do_write_object(ObjectStore::Transaction *t,
    coll_t coll, hobject_t obj) {

  size_t bytes = get_random_byte_amount(min_write_bytes, max_write_bytes);
  bufferlist bl;
  get_filled_byte_array(bl, bytes);
  t->write(coll, obj, 0, bl.length(), bl);
}

void WorkloadGenerator::do_setattr_object(ObjectStore::Transaction *t,
    coll_t coll, hobject_t obj) {

  size_t size;
  size = get_random_byte_amount(min_xattr_obj_bytes, max_xattr_obj_bytes);

  bufferlist bl;
  get_filled_byte_array(bl, size);
  t->setattr(coll, obj, "objxattr", bl);
}

void WorkloadGenerator::do_setattr_collection(ObjectStore::Transaction *t,
    coll_t coll) {

  size_t size;
  size = get_random_byte_amount(min_xattr_coll_bytes, max_xattr_coll_bytes);

  bufferlist bl;
  get_filled_byte_array(bl, size);
  t->collection_setattr(coll, "collxattr", bl);
}

void WorkloadGenerator::do_append_log(ObjectStore::Transaction *t,
    coll_t coll) {

  bufferlist bl;
  get_filled_byte_array(bl, log_append_bytes);
  hobject_t log_obj = get_coll_meta_object(coll);

  struct stat st;
  int err = m_store->stat(META_COLL, log_obj, &st);
  assert(err >= 0);
  t->write(META_COLL, log_obj, st.st_size, bl.length(), bl);
}

void WorkloadGenerator::do_destroy_collection(ObjectStore::Transaction *t) {

}

void WorkloadGenerator::do_create_collection(ObjectStore::Transaction *t) {

}

bool WorkloadGenerator::allow_collection_destruction() {
  return (this->m_allow_coll_destruction);
}

void WorkloadGenerator::run() {

  do {
    m_lock.Lock();
    wait_for_ready();

    int coll_nr = get_random_collection_nr();
    int obj_nr = get_random_object_nr(coll_nr);

    bool do_destroy = false;
    if (allow_collection_destruction()) {
      int rnd_probability = (1 + (rand() % 100));

      if (rnd_probability <= m_prob_destroy_coll)
        do_destroy = true;
    }

    coll_t coll = get_collection_by_nr(coll_nr);
    hobject_t obj = get_object_by_nr(obj_nr);

    ObjectStore::Transaction *t = new ObjectStore::Transaction;

    do_write_object(t, coll, obj);
    do_setattr_object(t, coll, obj);
    do_setattr_collection(t, coll);
    do_append_log(t, coll);

    m_store->queue_transaction(&m_osr[coll_nr], t,
        new C_WorkloadGeneratorOnReadable(this, t));

    m_in_flight++;

    m_lock.Unlock();
  } while (true);
}

void WorkloadGenerator::print_results() {

}

int main(int argc, const char *argv[]) {
  vector<const char*> args;
  args.push_back("--osd-journal-size");
  args.push_back("400");
  args.push_back("--osd-data");
  args.push_back("workload_gen_dir");
  args.push_back("--osd-journal");
  args.push_back("workload_gen_journal");
  argv_to_vec(argc, argv, args);

  global_init(args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);
  g_ceph_context->_conf->apply_changes(NULL);

  WorkloadGenerator *wrkldgen_ptr = new WorkloadGenerator(args);
  wrkldgen.reset(wrkldgen_ptr);
  wrkldgen->run();
  wrkldgen->print_results();

  return 0;
}
